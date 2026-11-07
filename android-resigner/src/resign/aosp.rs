use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufWriter, Read, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};

use crate::{archive::Zip, io::ReadAt};
use super::blob::{self, Blob};

const BLOCK: u64 = 4096;
const MAX_SMALL: u64 = 64 << 20;
const MAX_LIST: u64 = 8 << 20;
const MAX_DIRECT: u64 = 512 << 20;
const MEMORY_LIMIT: u64 = 4 << 30;
const MAX_IMAGE: u64 = 16 << 30;
const MAX_TOTAL_NEW: u64 = 16 << 30;
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
    layout: DynamicLayout,
    lists: BTreeMap<String, TransferList>,
    disk: BTreeSet<String>,
    scratch: PathBuf,
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

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
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
    pub(super) fn open(path: &Path, scratch: &Path) -> Result<Self> {
        let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let zip = Zip::open(source).with_context(|| format!("reading {}", path.display()))?;
        let info = metadata(&Self::read_entry(&zip, "META-INF/com/android/metadata", MAX_SMALL)?)?;
        if info.get("ota-type").map(String::as_str) != Some("BLOCK") { bail!("AOSP ZIP is not a BLOCK OTA") }
        let layout = dynamic(&Self::read_entry(&zip, "dynamic_partitions_op_list", MAX_SMALL)?)?;
        let mut lists = BTreeMap::new();
        let mut disk = BTreeSet::new();
        let mut memory = 0u64;
        let mut total_new = 0u64;
        for name in layout.partitions.keys() {
            let raw = Self::read_entry(&zip, &format!("{name}.transfer.list"), MAX_LIST)?;
            let list = transfer(std::str::from_utf8(&raw).context("transfer list is not UTF-8")?)?;
            let bytes = list.new_blocks.checked_mul(BLOCK).context("AOSP new-data size overflow")?;
            if bytes > layout.partitions[name].size { bail!("AOSP new-data exceeds partition {name}") }
            total_new = total_new.checked_add(bytes).filter(|size| *size <= MAX_TOTAL_NEW).context("AOSP ZIP has too much new-data")?;
            if bytes > MEMORY_LIMIT || bytes > usize::MAX as u64
                || memory.checked_add(bytes).is_none_or(|size| size > MEMORY_LIMIT) {
                disk.insert(name.clone());
            } else {
                memory += bytes;
            }
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
        Ok(Self { zip, layout, lists, disk, scratch: scratch.to_owned() })
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

    pub(super) fn layout(&self) -> &DynamicLayout { &self.layout }

    pub(super) fn empty_super(&self) -> Result<Vec<u8>> {
        let data = Self::read_entry(&self.zip, "unsparse_super_empty.img", MAX_SMALL)?;
        if data.get(..4) != Some(b"gDla".as_slice()) { bail!("unsparse_super_empty.img has no LP geometry") }
        Ok(data)
    }

    pub(super) fn physical(&self, name: &str) -> Result<Option<Blob>> {
        let Some(entry) = self.zip.find_exact(name)? else { return Ok(None) };
        if entry.size == 0 || entry.size > MAX_DIRECT || entry.size > usize::MAX as u64 {
            bail!("invalid AOSP image size for {}", entry.name)
        }
        Ok(Some(blob::bytes(Self::read_entry(&self.zip, &entry.name, MAX_DIRECT)?)))
    }

    pub(super) fn logical(&self, name: &str) -> Result<Option<AospImage>> {
        let name = name.strip_suffix(".img").unwrap_or(name);
        let Some(partition) = self.layout.partitions.get(name) else { return Ok(None) };
        let list = self.lists.get(name).context("AOSP transfer list disappeared")?.clone();
        let expected = list.new_blocks.checked_mul(BLOCK).context("AOSP new-data size overflow")?;
        if expected > partition.size || expected > MAX_IMAGE { bail!("invalid AOSP new-data size for {name}") }
        let entry = self.zip.exact(&format!("{name}.new.dat.br"))?;
        let reader = self.zip.reader(entry)?;
        let mut decoder = brotli::Decompressor::new(reader, 64 << 10).take(expected + 1);
        let source = if self.disk.contains(name) {
            let file = tempfile::tempfile_in(&self.scratch).context("creating AOSP scratch file")?;
            let mut output = BufWriter::with_capacity(1 << 20, file);
            let size = std::io::copy(&mut decoder, &mut output).with_context(|| format!("writing AOSP new-data for {name}"))?;
            output.flush().with_context(|| format!("flushing AOSP new-data for {name}"))?;
            let file = output.into_inner().map_err(|error| error.into_error())?;
            if size != expected || file.metadata()?.len() != expected { bail!("AOSP new-data size mismatch for {name}") }
            blob::file_handle(file)
        } else {
            if expected > usize::MAX as u64 { bail!("AOSP new-data is too large for memory") }
            let mut decoded = Vec::new();
            decoded.try_reserve_exact(expected as usize).context("AOSP new-data allocation failed")?;
            decoder.read_to_end(&mut decoded)?;
            if decoded.len() as u64 != expected { bail!("AOSP new-data size mismatch for {name}") }
            blob::bytes(decoded)
        };
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
