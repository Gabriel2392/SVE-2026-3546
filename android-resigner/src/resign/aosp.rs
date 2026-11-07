use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    ops::Range,
    path::Path,
    sync::Arc,
};

use anyhow::{bail, Context, Result};

use crate::{archive::Zip, io::ReadAt};
use super::blob::{self, Blob};

const BLOCK: u64 = 4096;
const MAX_SMALL: u64 = 64 << 20;
const MAX_LIST: u64 = 8 << 20;
const MAX_DIRECT: u64 = 512 << 20;
const MAX_IMAGE: u64 = 4 << 30;
const MAX_TOTAL_NEW: u64 = 4 << 30;
const MAX_UPDATER: u64 = 1 << 20;
const MAX_TOKENS: usize = 262_144;
const MAX_IF_DEPTH: usize = 64;
const MAX_IF_BLOCKS: usize = 4096;
const RANGE_LIMIT: usize = 262_144;

#[derive(Clone, Debug)]
pub(super) struct DynamicPartition {
    pub group: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub(super) struct DynamicLayout {
    pub groups: BTreeMap<String, u64>,
    pub partitions: BTreeMap<String, DynamicPartition>,
}

pub(super) struct AospImage {
    pub image: Blob,
    pub size: u64,
}

pub(super) struct AospZip {
    zip: Zip,
    metadata: BTreeMap<String, String>,
    layout: DynamicLayout,
    updater: String,
    lists: BTreeMap<String, TransferList>,
}

#[derive(Clone)]
enum TransferOperation {
    New(Vec<Range<u64>>),
    Zero(Vec<Range<u64>>),
    Erase,
}

#[derive(Clone)]
struct TransferList {
    new_blocks: u64,
    operations: Vec<TransferOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token { Word(String), Text(String), Eq, Ne, And, Or, Open, Close, Comma, Semi, Other }

#[derive(Clone, Debug)]
struct IfBlock { all: Range<usize>, condition: Range<usize>, body: Range<usize> }

struct Target { model: String, modem: bool }

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn lex(text: &str) -> Result<Vec<Token>> {
    let raw = text.as_bytes(); let mut out = Vec::new(); let mut at = 0;
    while at < raw.len() {
        if out.len() >= MAX_TOKENS { bail!("updater has too many tokens") }
        if raw[at].is_ascii_whitespace() { at += 1; continue }
        if raw[at] == b'#' { at = text[at..].find('\n').map_or(raw.len(), |end| at + end + 1); continue }
        if raw[at] == b'"' {
            at += 1; let mut value = String::new(); let mut closed = false;
            while at < raw.len() {
                if raw[at] == b'"' { at += 1; closed = true; break }
                let byte = if raw[at] == b'\\' {
                    at += 1; *raw.get(at).context("truncated updater string escape")?
                } else { raw[at] };
                if !byte.is_ascii() { bail!("non-ASCII updater string") }
                value.push(byte as char); at += 1;
            }
            if !closed { bail!("unterminated updater string") }
            out.push(Token::Text(value)); continue
        }
        let pair = raw.get(at..at + 2);
        if let Some(token) = match pair {
            Some(b"==") => Some(Token::Eq), Some(b"!=") => Some(Token::Ne),
            Some(b"&&") => Some(Token::And), Some(b"||") => Some(Token::Or), _ => None,
        } { out.push(token); at += 2; continue }
        if raw[at].is_ascii_alphanumeric() || raw[at] == b'_' {
            let start = at; at += 1;
            while at < raw.len() && (raw[at].is_ascii_alphanumeric() || raw[at] == b'_') { at += 1 }
            out.push(Token::Word(text[start..at].to_owned())); continue
        }
        out.push(match raw[at] { b'(' => Token::Open, b')' => Token::Close, b',' => Token::Comma, b';' => Token::Semi, _ => Token::Other });
        at += 1;
    }
    Ok(out)
}

fn if_blocks(tokens: &[Token]) -> Result<Vec<IfBlock>> {
    let mut stack = Vec::<(usize, usize, Option<usize>)>::new(); let mut out = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        match token {
            Token::Word(word) if word == "if" => {
                if stack.len() >= MAX_IF_DEPTH { bail!("updater if nesting is too deep") }
                stack.push((at, at + 1, None));
            }
            Token::Word(word) if word == "then" => {
                let top = stack.last_mut().context("updater then without if")?;
                if top.2.replace(at + 1).is_some() { bail!("duplicate updater then") }
            }
            Token::Word(word) if word == "endif" => {
                let (start, condition, body) = stack.pop().context("updater endif without if")?;
                let body = body.context("updater if without then")?;
                if !matches!(tokens.get(at + 1), Some(Token::Semi)) { bail!("updater endif without semicolon") }
                if out.len() >= MAX_IF_BLOCKS { bail!("updater has too many if blocks") }
                out.push(IfBlock { all: start..at + 2, condition: condition..body - 1, body: body..at });
            }
            Token::Word(word) if word == "else" => bail!("updater else is unsupported"),
            _ => {}
        }
    }
    if !stack.is_empty() { bail!("unterminated updater if") }
    Ok(out)
}

fn parentheses(tokens: &[Token]) -> Result<Vec<Option<usize>>> {
    let mut pairs = vec![None; tokens.len()]; let mut stack = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        match token {
            Token::Open => {
                if stack.len() >= MAX_IF_DEPTH { bail!("updater expression nesting is too deep") }
                stack.push(at);
            }
            Token::Close => {
                let open = stack.pop().context("updater close parenthesis without open")?;
                pairs[open] = Some(at); pairs[at] = Some(open);
            }
            _ => {}
        }
    }
    if !stack.is_empty() { bail!("unterminated updater parenthesis") }
    Ok(pairs)
}

fn parenthesized(tokens: &[Token]) -> Vec<bool> {
    let mut depth = 0usize;
    tokens.iter().map(|token| {
        if matches!(token, Token::Close) { depth -= 1 }
        let inside = depth != 0;
        if matches!(token, Token::Open) { depth += 1 }
        inside
    }).collect()
}

fn parents(blocks: &[IfBlock]) -> Vec<Option<usize>> {
    blocks.iter().map(|child| {
        blocks.iter().enumerate().filter(|(_, block)| block.all.start < child.all.start && child.all.end <= block.all.end)
            .min_by_key(|(_, block)| block.all.end - block.all.start).map(|(index, _)| index)
    }).collect()
}

fn covered(len: usize, blocks: &[IfBlock]) -> Vec<bool> {
    let mut events = vec![0i32; len + 1];
    for block in blocks { events[block.all.start] += 1; events[block.all.end] -= 1; }
    let mut depth = 0i32;
    events.into_iter().take(len).map(|value| { depth += value; depth != 0 }).collect()
}

fn comparison(tokens: &[Token], at: usize) -> Option<(&str, bool, &str, usize)> {
    match tokens.get(at..at + 6)? {
        [Token::Word(get), Token::Open, Token::Text(property), Token::Close, op, Token::Text(value)] if get == "getprop" => {
            let equal = match op { Token::Eq => true, Token::Ne => false, _ => return None };
            Some((property, equal, value, at + 6))
        }
        _ => None,
    }
}

fn model_guard(tokens: &[Token], range: Range<usize>) -> Option<String> {
    let (property, equal, value, end) = comparison(tokens, range.start)?;
    let model = value.strip_prefix("SM-")?;
    (equal && property == "ro.boot.em.model" && end == range.end && (4..=16).contains(&model.len())
        && model.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
        .then(|| model.to_owned())
}

fn bootloaders(tokens: &[Token], range: Range<usize>) -> Option<Vec<String>> {
    fn term(tokens: &[Token], end: usize, at: &mut usize, out: &mut Vec<String>, depth: usize) -> Option<()> {
        if matches!(tokens.get(*at), Some(Token::Open)) {
            if depth >= MAX_IF_DEPTH { return None }
            *at += 1; expression(tokens, end, at, out, depth + 1)?;
            if *at >= end || !matches!(tokens.get(*at), Some(Token::Close)) { return None }
            *at += 1; return Some(())
        }
        let (property, equal, value, next) = comparison(tokens, *at)?;
        if next > end || equal || property != "ro.boot.bootloader" || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') { return None }
        out.push(value.to_owned()); *at = next; Some(())
    }
    fn expression(tokens: &[Token], end: usize, at: &mut usize, out: &mut Vec<String>, depth: usize) -> Option<()> {
        term(tokens, end, at, out, depth)?;
        while *at < end {
            if matches!(tokens.get(*at), Some(Token::Close)) { break }
            if !matches!(tokens.get(*at), Some(Token::And)) { return None }
            *at += 1; term(tokens, end, at, out, depth)?;
        }
        Some(())
    }
    let mut at = range.start; let mut out = Vec::new(); expression(tokens, range.end, &mut at, &mut out, 0)?;
    (at == range.end && !out.is_empty()).then_some(out)
}

fn call(tokens: &[Token], pairs: &[Option<usize>], at: usize, name: &str) -> Option<Range<usize>> {
    if !matches!(tokens.get(at), Some(Token::Word(word)) if word == name) || !matches!(tokens.get(at + 1), Some(Token::Open)) { return None }
    Some(at + 2..pairs.get(at + 1).copied().flatten()?)
}

fn device_assert(tokens: &[Token], pairs: &[Option<usize>], range: Range<usize>) -> Option<BTreeSet<String>> {
    let mut devices = BTreeSet::new(); let mut at = range.start; let mut abort = false;
    while at < range.end {
        if let Some((property, true, value, next)) = comparison(tokens, at) {
            if !matches!(property, "ro.product.device" | "ro.build.product") || !valid_name(value) { return None }
            devices.insert(value.to_owned()); at = next;
        } else if let Some(body) = call(tokens, pairs, at, "abort") {
            if body.end >= range.end { return None }
            abort = true; at = body.end + 1;
        } else { return None }
        if abort && matches!(tokens.get(at), Some(Token::Semi)) { at += 1 }
        if at == range.end { break }
        if abort || !matches!(tokens.get(at), Some(Token::Or)) { return None }
        at += 1;
    }
    (abort && !devices.is_empty()).then_some(devices)
}

fn abort_body(tokens: &[Token], pairs: &[Option<usize>], range: Range<usize>) -> bool {
    call(tokens, pairs, range.start, "abort").is_some_and(|body| {
        body.end + 2 == range.end && matches!(tokens.get(body.end + 1), Some(Token::Semi))
    })
}

fn ranges(value: &str) -> Result<Vec<Range<u64>>> {
    let values = value.split(',').map(|value| value.parse::<u64>().context("invalid transfer-list range"))
        .collect::<Result<Vec<_>>>()?;
    let count = usize::try_from(*values.first().context("empty transfer-list range")?).context("transfer-list range count is too large")?;
    if count == 0 || count % 2 != 0 || count != values.len() - 1 || count / 2 > RANGE_LIMIT { bail!("invalid transfer-list range count") }
    values[1..].chunks_exact(2).map(|pair| {
        if pair[0] >= pair[1] { bail!("empty or reversed transfer-list range") }
        Ok(pair[0]..pair[1])
    }).collect()
}

fn blocks(ranges: &[Range<u64>]) -> Result<u64> {
    ranges.iter().try_fold(0u64, |sum, range| sum.checked_add(range.end - range.start).context("transfer-list block count overflow"))
}

fn transfer(text: &str) -> Result<TransferList> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 4 { bail!("transfer list has fewer than four header lines") }
    let version = lines[0].trim().parse::<u8>().context("invalid transfer-list version")?;
    if !(3..=4).contains(&version) { bail!("unsupported transfer-list version {version}") }
    let written_blocks = lines[1].trim().parse::<u64>().context("invalid transfer-list block count")?;
    if lines[2].trim() != "0" || lines[3].trim() != "0" { bail!("incremental transfer-list stash data is unsupported") }
    let mut operations = Vec::new();
    let mut range_count = 0usize;
    let mut new_blocks = 0u64;
    let mut actual = 0u64;
    for line in lines[4..].iter().map(|line| line.trim()).filter(|line| !line.is_empty()) {
        let (kind, value) = line.split_once(' ').context("invalid transfer-list command")?;
        let list = ranges(value.trim())?;
        range_count = range_count.checked_add(list.len()).filter(|count| *count <= RANGE_LIMIT).context("transfer list has too many ranges")?;
        match kind {
            "new" => {
                let count = blocks(&list)?;
                new_blocks = new_blocks.checked_add(count).context("transfer-list block count overflow")?;
                actual = actual.checked_add(count).context("transfer-list block count overflow")?;
                operations.push(TransferOperation::New(list));
            }
            "zero" => {
                actual = actual.checked_add(blocks(&list)?).context("transfer-list block count overflow")?;
                operations.push(TransferOperation::Zero(list));
            }
            "erase" => operations.push(TransferOperation::Erase),
            _ => bail!("unsupported transfer-list command {kind}"),
        }
    }
    if actual != written_blocks { bail!("transfer-list written block count mismatch") }
    Ok(TransferList { new_blocks, operations })
}

fn metadata(data: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(data).context("OTA metadata is not UTF-8")?;
    let mut output = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once('=').context("invalid OTA metadata line")?;
        if !valid_name(name) || output.insert(name.to_owned(), value.trim().to_owned()).is_some() { bail!("invalid or duplicate OTA metadata key") }
    }
    Ok(output)
}

fn dynamic(data: &[u8]) -> Result<DynamicLayout> {
    let text = std::str::from_utf8(data).context("dynamic partition list is not UTF-8")?;
    let mut groups = BTreeMap::new();
    let mut members = BTreeMap::new();
    let mut sizes = BTreeMap::new();
    let mut reset = false;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            ["remove_all_groups"] if !reset && groups.is_empty() && members.is_empty() && sizes.is_empty() => reset = true,
            ["add_group", group, size] if reset && valid_name(group) => {
                let size = size.parse::<u64>().context("invalid dynamic group size")?;
                if size == 0 || groups.insert((*group).to_owned(), size).is_some() { bail!("invalid or duplicate dynamic group") }
            }
            ["add", part, group] if reset && valid_name(part) && valid_name(group) && groups.contains_key(*group) => {
                if members.insert((*part).to_owned(), (*group).to_owned()).is_some() { bail!("duplicate dynamic partition") }
            }
            ["resize", part, size] if reset && members.contains_key(*part) => {
                let size = size.parse::<u64>().context("invalid dynamic partition size")?;
                if size == 0 || size % BLOCK != 0 || size > MAX_IMAGE || sizes.insert((*part).to_owned(), size).is_some() {
                    bail!("invalid or duplicate dynamic partition size")
                }
            }
            _ => bail!("unsupported dynamic partition operation: {line}"),
        }
    }
    if !reset || members.is_empty() || members.keys().collect::<BTreeSet<_>>() != sizes.keys().collect::<BTreeSet<_>>() {
        bail!("incomplete dynamic partition layout")
    }
    let mut used = BTreeMap::<String, u64>::new();
    let partitions = members.into_iter().map(|(name, group)| {
        let size = sizes[&name];
        let total = used.entry(group.clone()).or_default();
        *total = total.checked_add(size).context("dynamic group size overflow")?;
        Ok((name, DynamicPartition { group, size }))
    }).collect::<Result<BTreeMap<_, _>>>()?;
    for (group, size) in used {
        if size > groups[&group] { bail!("dynamic partitions exceed group {group}") }
    }
    Ok(DynamicLayout { groups, partitions })
}

impl AospZip {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let zip = Zip::open(source).with_context(|| format!("reading {}", path.display()))?;
        let metadata = metadata(&Self::read_entry(&zip, "META-INF/com/android/metadata", MAX_SMALL)?)?;
        if metadata.get("ota-type").map(String::as_str) != Some("BLOCK") { bail!("AOSP ZIP is not a BLOCK OTA") }
        for name in ["boot.img", "vendor_boot.img", "dtbo.img", "recovery.img", "vbmeta.img"] {
            let entry = zip.exact(name)?;
            if entry.directory || entry.size == 0 || entry.size > MAX_DIRECT { bail!("invalid AOSP image {name}") }
        }
        let layout = dynamic(&Self::read_entry(&zip, "dynamic_partitions_op_list", MAX_SMALL)?)?;
        let updater = String::from_utf8(Self::read_entry(&zip, "META-INF/com/google/android/updater-script", MAX_UPDATER)?).context("updater-script is not UTF-8")?;
        let mut lists = BTreeMap::new();
        let mut total_new = 0u64;
        for name in layout.partitions.keys() {
            let raw = Self::read_entry(&zip, &format!("{name}.transfer.list"), MAX_LIST)?;
            let list = transfer(std::str::from_utf8(&raw).context("transfer list is not UTF-8")?)?;
            let bytes = list.new_blocks.checked_mul(BLOCK).context("AOSP new-data size overflow")?;
            if bytes > layout.partitions[name].size { bail!("AOSP new-data exceeds partition {name}") }
            total_new = total_new.checked_add(bytes).filter(|size| *size <= MAX_TOTAL_NEW).context("AOSP ZIP requires too much memory")?;
            let data = zip.exact(&format!("{name}.new.dat.br"))?;
            if data.method != 0 || data.size == 0 || data.size > MAX_IMAGE { bail!("invalid AOSP new-data member for {name}") }
            zip.verify(data).with_context(|| format!("checking AOSP new-data for {name}"))?;
            if let Some(patch) = zip.find_exact(&format!("{name}.patch.dat"))? {
                if patch.size != 0 { bail!("incremental AOSP patch data is unsupported for {name}") }
            }
            lists.insert(name.clone(), list);
        }
        let empty = zip.exact("unsparse_super_empty.img")?;
        if empty.size < 4 || empty.size > MAX_SMALL { bail!("invalid unsparse_super_empty.img size") }
        Ok(Self { zip, metadata, layout, updater, lists })
    }

    fn read_entry(zip: &Zip, name: &str, limit: u64) -> Result<Vec<u8>> {
        let entry = zip.exact(name)?;
        if entry.directory || entry.size > limit || entry.size > usize::MAX as u64 { bail!("invalid ZIP member size for {name}") }
        let mut output = Vec::new();
        output.try_reserve_exact(entry.size as usize).context("ZIP member allocation failed")?;
        zip.reader(entry)?.read_to_end(&mut output)?;
        if output.len() as u64 != entry.size { bail!("ZIP member size mismatch for {name}") }
        Ok(output)
    }

    fn metadata(&self, name: &str) -> Option<&str> { self.metadata.get(name).map(String::as_str) }

    pub(super) fn layout(&self) -> &DynamicLayout { &self.layout }

    fn target(&self, firmware: &str) -> Result<Target> {
        let tokens = lex(&self.updater)?; let pairs = parentheses(&tokens)?; let nested = parenthesized(&tokens); let policy = if_blocks(&tokens)?;
        let parents = parents(&policy); let covered = covered(tokens.len(), &policy);
        let mut assertions = Vec::new();
        for at in 0..tokens.len() {
            if covered[at] || nested[at] { continue }
            let Some(body) = call(&tokens, &pairs, at, "assert") else { continue };
            if let Some(devices) = device_assert(&tokens, &pairs, body) { assertions.push(devices) }
        }
        if assertions.len() != 1 { bail!("AOSP updater has no unique device policy") }
        let asserted = assertions.pop().unwrap();
        let mut devices = BTreeSet::new();
        let listed = self.metadata("pre-device").context("AOSP ZIP has no target device")?;
        for device in listed.split([',', '|']).map(str::trim) {
            if !valid_name(device) || !devices.insert(device) || !asserted.contains(device) {
                bail!("AOSP target metadata does not match its updater")
            }
        }
        if devices.is_empty() { bail!("AOSP ZIP has no target device") }

        let mut matches = Vec::new();
        for (outer_index, outer) in policy.iter().enumerate() {
            if parents[outer_index].is_some() { continue }
            let Some(model) = model_guard(&tokens, outer.condition.clone()) else { continue };
            let Some(suffix) = firmware.strip_prefix(&model) else { continue };
            if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') { continue }
            for (inner_index, inner) in policy.iter().enumerate() {
                if parents[inner_index] != Some(outer_index) { continue }
                let Some(values) = bootloaders(&tokens, inner.condition.clone()) else { continue };
                if abort_body(&tokens, &pairs, inner.body.clone()) && values.iter().all(|value| value.starts_with(&model))
                    && values.iter().any(|value| value == firmware) { matches.push(model.clone()) }
            }
        }
        if matches.len() != 1 { bail!("AOSP ZIP does not support bootloader {firmware}") }
        let model = matches.pop().unwrap(); let member = format!("modem.bin_SM-{model}"); let mut modem = Vec::new();
        for (outer_index, outer) in policy.iter().enumerate() {
            if parents[outer_index].is_some() || model_guard(&tokens, outer.condition.clone()).as_deref() != Some(model.as_str()) { continue }
            for at in outer.body.clone() {
                let Some(body) = call(&tokens, &pairs, at, "package_extract_file") else { continue };
                if body.end > outer.body.end { bail!("AOSP modem policy crosses its model block") }
                if !matches!(tokens.get(body.start), Some(Token::Text(value)) if value == &member) { continue }
                if modem.len() >= 64 || policy.iter().any(|block| block.condition.contains(&at)) {
                    bail!("unsupported AOSP modem policy")
                }
                let owner = policy.iter().enumerate().filter(|(_, block)| block.body.contains(&at))
                    .min_by_key(|(_, block)| block.all.end - block.all.start);
                let guard = match owner {
                    Some((index, _)) if index == outer_index => None,
                    Some((index, block)) if parents[index] == Some(outer_index) && body.end <= block.body.end => Some(block),
                    _ => bail!("unsupported AOSP modem policy"),
                };
                modem.push(match guard {
                    Some(inner) => !bootloaders(&tokens, inner.condition.clone()).context("unsupported AOSP modem policy")?
                        .iter().any(|value| value == firmware),
                    None => true,
                });
            }
        }
        if modem.len() > 1 { bail!("ambiguous AOSP modem policy for {model}") }
        Ok(Target { model, modem: modem.pop().unwrap_or(false) })
    }

    pub(super) fn validate_target(&self, firmware: &str) -> Result<()> { self.target(firmware).map(drop) }

    pub(super) fn empty_super(&self) -> Result<Vec<u8>> {
        let data = Self::read_entry(&self.zip, "unsparse_super_empty.img", MAX_SMALL)?;
        if data.get(..4) != Some(b"gDla".as_slice()) { bail!("unsparse_super_empty.img has no LP geometry") }
        Ok(data)
    }

    pub(super) fn physical(&self, name: &str, firmware: &str) -> Result<Option<Blob>> {
        let member = if name == "modem.bin" {
            let target = self.target(firmware)?;
            if !target.modem { return Ok(None) }
            format!("modem.bin_SM-{}", target.model)
        } else {
            name.to_owned()
        };
        let Some(entry) = self.zip.find_exact(&member)? else { return Ok(None) };
        if entry.size == 0 || entry.size > MAX_DIRECT || entry.size > usize::MAX as u64 { bail!("invalid AOSP image size for {member}") }
        Ok(Some(blob::bytes(Self::read_entry(&self.zip, &member, MAX_DIRECT)?)))
    }

    pub(super) fn logical(&self, name: &str) -> Result<Option<AospImage>> {
        let name = name.strip_suffix(".img").unwrap_or(name);
        let Some(partition) = self.layout.partitions.get(name) else { return Ok(None) };
        let list = self.lists.get(name).context("AOSP transfer list disappeared")?.clone();
        let expected = list.new_blocks.checked_mul(BLOCK).context("AOSP new-data size overflow")?;
        if expected > partition.size || expected > MAX_IMAGE || expected > usize::MAX as u64 { bail!("invalid AOSP new-data size for {name}") }
        let entry = self.zip.exact(&format!("{name}.new.dat.br"))?;
        let reader = self.zip.reader(entry)?;
        let mut decoder = brotli::Decompressor::new(reader, 64 << 10).take(expected + 1);
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(expected as usize).context("AOSP new-data allocation failed")?;
        decoder.read_to_end(&mut decoded)?;
        if decoded.len() as u64 != expected { bail!("AOSP new-data size mismatch for {name}") }
        let source = blob::bytes(decoded);
        let mut at = 0u64;
        let mut used = Vec::new();
        let mut changes = Vec::new();
        for operation in list.operations {
            match operation {
                TransferOperation::New(ranges) => for range in ranges {
                    let start = range.start.checked_mul(BLOCK).context("AOSP extent offset overflow")?;
                    let len = (range.end - range.start).checked_mul(BLOCK).context("AOSP extent size overflow")?;
                    let end = start.checked_add(len).filter(|end| *end <= partition.size).context("AOSP new extent exceeds partition")?;
                    used.push(start..end);
                    changes.push((start, blob::region(source.clone(), at, len)?));
                    at = at.checked_add(len).context("AOSP new-data offset overflow")?;
                },
                TransferOperation::Zero(ranges) => for range in ranges {
                    let start = range.start.checked_mul(BLOCK).context("AOSP zero offset overflow")?;
                    let len = (range.end - range.start).checked_mul(BLOCK).context("AOSP zero size overflow")?;
                    let end = start.checked_add(len).filter(|end| *end <= partition.size).context("AOSP zero extent exceeds partition")?;
                    used.push(start..end);
                },
                TransferOperation::Erase => {}
            }
        }
        if at != expected { bail!("unused AOSP new-data bytes for {name}") }
        used.sort_by_key(|range| range.start);
        if used.windows(2).any(|pair| pair[0].end > pair[1].start) { bail!("overlapping AOSP extents for {name}") }
        let image = blob::overlay(blob::zeroes(partition.size), changes)?;
        Ok(Some(AospImage { image, size: partition.size }))
    }
}
