use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
    thread::{self, JoinHandle},
    time::SystemTime,
};

use anyhow::{bail, Context, Result};
use md5::{Digest, Md5};

use crate::archive::safe_path;
use super::{archive::TarMd5, blob::Blob};

const BLOCK: u64 = 512;
const RECORD: u64 = 20 * BLOCK;
const BUFFER: usize = 8 << 20;
const LZ4_MAGIC: [u8; 4] = 0x184d_2204u32.to_le_bytes();

pub(super) struct UpdateOptions {
    pub base: PathBuf,
    pub changed: BTreeMap<String, Blob>,
    pub dependencies: BTreeMap<String, Blob>,
    pub plain: Option<(String, Vec<u8>)>,
    pub output: PathBuf,
    pub incremental: bool,
    pub force: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct UpdateResult {
    pub path: PathBuf,
    pub members: Vec<String>,
}

pub(super) struct Staged {
    temp: Partial,
    output: PathBuf,
    members: Vec<String>,
    force: bool,
}

impl Staged {
    pub(super) fn output(&self) -> &Path { &self.output }
    pub(super) fn force(&self) -> bool { self.force }

    pub(super) fn publish(mut self) -> Result<UpdateResult> {
        if self.output.exists() && !self.force { bail!("output already exists: {}", self.output.display()) }
        fs::rename(&self.temp.path, &self.output).with_context(|| format!("publishing {}", self.output.display()))?;
        self.temp.keep = true;
        Ok(UpdateResult { path: self.output.clone(), members: std::mem::take(&mut self.members) })
    }
}

fn safe_name(name: &str) -> bool {
    !name.is_empty() && name.is_ascii() && name.len() <= 95 && !name.contains('/') && !name.contains('\\')
        && !matches!(name, "." | "..") && !name.ends_with(".lz4")
}

fn tar_name(name: &str) -> String { format!("{name}.lz4") }

fn number(field: &[u8]) -> Result<u64> {
    if field.first().copied().unwrap_or(0) & 0x80 != 0 {
        if field[0] & 0x40 != 0 { bail!("negative tar number") }
        return field.iter().enumerate().try_fold(0u64, |value, (index, &byte)| {
            value.checked_mul(256).and_then(|value| value.checked_add(if index == 0 { byte & 0x7f } else { byte } as u64))
                .context("tar number overflow")
        });
    }
    let mut value = 0u64;
    for &byte in field.iter().skip_while(|&&byte| matches!(byte, 0 | b' ')) {
        if matches!(byte, 0 | b' ') { break }
        if !(b'0'..=b'7').contains(&byte) { bail!("invalid tar octal number") }
        value = value.checked_mul(8).and_then(|value| value.checked_add((byte - b'0') as u64)).context("tar number overflow")?;
    }
    Ok(value)
}

fn set_number(field: &mut [u8], mut value: u64) -> Result<()> {
    if u128::from(value) < 8u128.pow((field.len() - 1) as u32) {
        field.copy_from_slice(format!("{:0width$o}\0", value, width = field.len() - 1).as_bytes());
        return Ok(())
    }
    field.fill(0);
    for byte in field[1..].iter_mut().rev() { *byte = value as u8; value >>= 8; }
    if value != 0 { bail!("GNU tar numeric field overflow") }
    field[0] = 0x80;
    Ok(())
}

fn checksum(header: &[u8; 512]) -> Result<()> {
    let expected = number(&header[148..156])?;
    let actual: u64 = header.iter().enumerate().map(|(index, &byte)| if (148..156).contains(&index) { b' ' } else { byte }).map(u64::from).sum();
    if expected != actual { bail!("tar header checksum mismatch") }
    Ok(())
}

fn text(field: &[u8]) -> Result<&str> {
    let end = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).context("tar member name is not UTF-8")
}

fn header_name(header: &[u8; 512]) -> Result<(String, u8)> {
    checksum(header)?;
    let kind = header[156];
    if !matches!(kind, 0 | b'0' | b'5') { bail!("AP archive contains an unsafe member type") }
    let leaf = text(&header[..100])?;
    let prefix = text(&header[345..500])?;
    let name = if prefix.is_empty() { leaf.to_owned() } else { format!("{prefix}/{leaf}") };
    safe_path(&name).with_context(|| format!("unsafe AP member name {name:?}"))?;
    Ok((name, kind))
}

fn replace_size(mut header: [u8; 512], size: u64) -> Result<[u8; 512]> {
    set_number(&mut header[124..136], size)?;
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|&byte| byte as u64).sum();
    let encoded = format!("{checksum:06o}\0 ");
    if encoded.len() != 8 { bail!("tar checksum overflow") }
    header[148..156].copy_from_slice(encoded.as_bytes());
    Ok(header)
}

fn plain_header(name: &str, size: u64) -> Result<[u8; 512]> {
    if !name.is_ascii() || name.ends_with('/') || name.ends_with(".lz4") { bail!("unsafe plain member name {name:?}") }
    safe_path(name).with_context(|| format!("unsafe plain member name {name:?}"))?;
    let (prefix, leaf) = if name.len() <= 100 {
        ("", name)
    } else {
        name.match_indices('/').rev().find_map(|(at, _)| {
            let prefix = &name[..at]; let leaf = &name[at + 1..];
            (prefix.len() <= 155 && !leaf.is_empty() && leaf.len() <= 100).then_some((prefix, leaf))
        }).with_context(|| format!("plain member name is too long: {name}"))?
    };
    let mut header = [0; 512];
    header[..leaf.len()].copy_from_slice(leaf.as_bytes()); header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    set_number(&mut header[100..108], 0o644)?; set_number(&mut header[108..116], 0)?; set_number(&mut header[116..124], 0)?;
    set_number(&mut header[136..148], 0)?; header[156] = b'0'; header[257..265].copy_from_slice(b"ustar  \0");
    replace_size(header, size)
}

struct Trailer { tar_size: u64, hash_size: u64, archive: String, md5: String }

fn trailer(path: &Path) -> Result<Trailer> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let size = file.metadata()?.len();
    let tail_size = size.min(4096) as usize;
    let mut tail = vec![0; tail_size];
    file.seek(SeekFrom::End(-(tail_size as i64)))?;
    file.read_exact(&mut tail)?;
    if tail.last() != Some(&b'\n') { bail!("Odin MD5 trailer has no newline") }
    let separator = tail[..tail.len() - 1].windows(2).enumerate().rev().find_map(|(at, value)| {
        (value == b"  " && at >= 32 && tail[at - 32..at].iter().all(|byte| byte.is_ascii_hexdigit())).then_some(at)
    }).context("invalid Odin MD5 trailer")?;
    let line_start = separator.checked_sub(32).context("invalid Odin MD5 trailer")?;
    let line = &tail[line_start..];
    if line.len() < 36 || line[32..34] != *b"  " || !line[..32].iter().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid Odin MD5 trailer")
    }
    let archive = std::str::from_utf8(&line[34..line.len() - 1]).context("Odin trailer filename is not UTF-8")?;
    if archive.is_empty() || archive.contains('/') || archive.contains('\\') { bail!("invalid Odin trailer filename") }
    let tail_start = size.checked_sub(tail_size as u64).context("invalid Odin trailer size")?;
    let line_offset = tail_start.checked_add(line_start as u64).context("invalid Odin trailer offset")?;
    let before = &tail[..line_start];
    let marker = b"Show the build information\n";
    let (tar_size, hash_size) = if let Some(at) = before.windows(marker.len()).rposition(|value| value == marker) {
        let info = std::str::from_utf8(&before[at..]).context("Samsung build information is not UTF-8")?;
        let mut lines = info.lines();
        if lines.next() != Some("Show the build information") { bail!("invalid Samsung build information") }
        let build = lines.next().and_then(|line| line.strip_prefix("RBS BUILD_ID:")).context("Samsung build ID is missing")?;
        if build.is_empty() || !build.bytes().all(|byte| byte.is_ascii_digit()) { bail!("invalid Samsung build ID") }
        let declared = lines.next().and_then(|line| line.strip_prefix("original_tar_file_size:")).context("Samsung TAR size is missing")?;
        if lines.next().is_some() || declared.is_empty() || !declared.bytes().all(|byte| byte.is_ascii_digit()) { bail!("invalid Samsung TAR size") }
        let declared = declared.parse::<u64>().context("invalid Samsung TAR size")?;
        let info_offset = tail_start.checked_add(at as u64).context("invalid Samsung build information offset")?;
        if declared != info_offset { bail!("Samsung TAR size does not match its build information") }
        (declared, line_offset)
    } else {
        (line_offset, line_offset)
    };
    if tar_size == 0 || tar_size % RECORD != 0 { bail!("Odin TAR length is not record-aligned") }
    Ok(Trailer { tar_size, hash_size, archive: archive.to_owned(), md5: std::str::from_utf8(&line[..32])?.to_owned() })
}

fn md5(path: &Path, size: u64, expected: &str) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hash = Md5::new();
    let mut left = size; let mut buffer = vec![0; BUFFER];
    while left != 0 {
        crate::cancel::check()?;
        let count = buffer.len().min(left as usize); file.read_exact(&mut buffer[..count])?; hash.update(&buffer[..count]); left -= count as u64;
    }
    if !hex::encode(hash.finalize()).eq_ignore_ascii_case(expected) { bail!("invalid Odin TAR MD5") }
    Ok(())
}

type Key = (PathBuf, u64, SystemTime);

static VERIFIED: Mutex<Vec<Key>> = Mutex::new(Vec::new());
static PENDING: Mutex<Vec<(Key, JoinHandle<Result<()>>)>> = Mutex::new(Vec::new());

fn key(path: &Path) -> Result<Key> {
    let meta = fs::metadata(path).with_context(|| format!("opening {}", path.display()))?;
    Ok((fs::canonicalize(path)?, meta.len(), meta.modified()?))
}

fn join(handle: JoinHandle<Result<()>>) -> Result<()> { handle.join().map_err(|_| anyhow::anyhow!("MD5 worker panicked"))? }

fn verified(key: &Key) -> Result<bool> {
    let handle = {
        let mut pending = PENDING.lock().unwrap_or_else(|error| error.into_inner());
        pending.iter().position(|(item, _)| item == key).map(|at| pending.remove(at).1)
    };
    if let Some(handle) = handle { join(handle)?; VERIFIED.lock().unwrap_or_else(|error| error.into_inner()).push(key.clone()); }
    Ok(VERIFIED.lock().unwrap_or_else(|error| error.into_inner()).contains(key))
}

pub(super) fn parse_trailer(path: &Path) -> Result<(u64, String)> {
    let value = trailer(path)?; let key = key(path)?;
    if !verified(&key)? {
        md5(path, value.hash_size, &value.md5)?;
        VERIFIED.lock().unwrap_or_else(|error| error.into_inner()).push(key);
    }
    Ok((value.tar_size, value.archive))
}

pub(super) fn check_later(path: &Path) -> Result<(u64, String)> {
    let value = trailer(path)?; let key = key(path)?;
    let mut pending = PENDING.lock().unwrap_or_else(|error| error.into_inner());
    if !VERIFIED.lock().unwrap_or_else(|error| error.into_inner()).contains(&key) && !pending.iter().any(|(item, _)| item == &key) {
        let (path, size, expected) = (path.to_owned(), value.hash_size, value.md5);
        let handle = thread::spawn(move || md5(&path, size, &expected).with_context(|| format!("validating Odin trailer for {}", path.display())));
        pending.push((key, handle));
    }
    Ok((value.tar_size, value.archive))
}

pub(super) fn checked() -> Result<()> {
    let pending = std::mem::take(&mut *PENDING.lock().unwrap_or_else(|error| error.into_inner()));
    let mut result = Ok(());
    for (key, handle) in pending {
        match join(handle) {
            Ok(()) => VERIFIED.lock().unwrap_or_else(|error| error.into_inner()).push(key),
            Err(error) => if result.is_ok() { result = Err(error) },
        }
    }
    result
}

struct Partial { path: PathBuf, keep: bool }
impl Drop for Partial { fn drop(&mut self) { if !self.keep { let _ = fs::remove_file(&self.path); } } }

fn partial(output: &Path) -> Result<Partial> {
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let name = output.file_name().and_then(|name| name.to_str()).context("output filename is not UTF-8")?;
    for attempt in 0..100u32 {
        let path = parent.join(format!(".{name}.{}.{}.partial", std::process::id(), attempt));
        if !path.exists() { return Ok(Partial { path, keep: false }) }
    }
    bail!("cannot allocate output temporary file")
}

fn output_tar_name(path: &Path) -> Result<String> {
    let name = path.file_name().and_then(|name| name.to_str()).context("output filename is not UTF-8")?;
    Ok(name.strip_suffix(".md5").unwrap_or(name).to_owned())
}

pub(super) fn stage(options: UpdateOptions) -> Result<Staged> {
    if !options.base.is_file() { bail!("base AP archive does not exist: {}", options.base.display()) }
    let in_place = options.base == options.output
        || options.base.canonicalize().ok().as_ref() == options.output.canonicalize().ok().as_ref();
    if in_place && options.incremental { bail!("incremental output must not overwrite the base AP archive") }
    if options.output.exists() && !options.force { bail!("output already exists: {}", options.output.display()) }
    let (tar_size, _) = check_later(&options.base)?;
    let mut replacements = options.changed;
    for (name, image) in options.dependencies {
        if replacements.insert(name.clone(), image).is_some() { bail!("dependent image {name:?} is supplied twice") }
    }
    let plain = options.plain;
    if replacements.is_empty() && plain.is_none() { bail!("no replacement images or plain member") }
    for name in replacements.keys() { if !safe_name(name) { bail!("unsafe replacement image name {name:?}") } }
    if let Some((name, _)) = &plain { plain_header(name, 0)?; }

    let selected = replacements.keys().map(|name| tar_name(name)).collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new(); let mut paths = BTreeSet::new(); let mut emitted = Vec::new();
    let mut input = File::open(&options.base)?; let mut at = 0u64;
    let temporary = partial(&options.output)?;
    let file = OpenOptions::new().create_new(true).read(true).write(true).open(&temporary.path).with_context(|| format!("creating {}", temporary.path.display()))?;
    let mut output = TarMd5::new(file, &output_tar_name(&options.output)?);
    let mut zero_blocks = 0usize;
    while at + BLOCK <= tar_size {
        let mut header = [0; 512]; input.read_exact(&mut header)?; at += BLOCK;
        if header.iter().all(|&byte| byte == 0) { zero_blocks += 1; if zero_blocks == 2 { break } continue }
        if zero_blocks != 0 { bail!("non-zero tar header after an end block") }
        let (member, kind) = header_name(&header)?;
        if !seen.insert(member.clone()) { bail!("duplicate AP member {member}") }
        if !paths.insert(safe_path(&member)?) { bail!("duplicate AP member path {member}") }
        let size = number(&header[124..136])?;
        if kind == b'5' && size != 0 { bail!("AP directory member {member} has data") }
        let padded = size.checked_add(BLOCK - 1).map(|value| value / BLOCK * BLOCK).context("tar member size overflow")?;
        if at.checked_add(padded).filter(|&end| end <= tar_size).is_none() { bail!("AP member {member} exceeds archive") }
        let image = matches!(kind, 0 | b'0') && member.ends_with(".lz4");
        if image {
            let mut magic = [0; 4];
            if size >= 4 { input.read_exact(&mut magic)?; input.seek(SeekFrom::Current(-4))?; }
            if size < 4 || magic != LZ4_MAGIC { bail!("AP member {member} is not an LZ4 frame") }
        }
        let decoded = image.then(|| member.strip_suffix(".lz4").unwrap());
        let replacement = decoded.and_then(|name| replacements.get(name).cloned());
        let plain_data = plain.as_ref().filter(|(name, _)| name == &member).map(|(_, data)| data.as_slice());
        if selected.contains(&member) && (!image || replacement.is_none()) { bail!("replacement target {member} is not a regular LZ4 image") }
        if plain_data.is_some() && !matches!(kind, 0 | b'0') { bail!("plain replacement target {member} is not a regular file") }
        let include = !options.incremental || selected.contains(&member) || plain_data.is_some();
        if include {
            if let Some(source) = replacement {
                output.lz4_with(|size| replace_size(header, size), source)?; emitted.push(decoded.unwrap().to_owned());
            } else if let Some(data) = plain_data {
                output.plain(&replace_size(header, data.len() as u64)?, data)?;
            } else {
                output.bytes(&header)?; output.copy(&mut input, padded)?;
                at += padded; continue
            }
        }
        input.seek(SeekFrom::Current(i64::try_from(padded).context("tar member seek overflow")?))?;
        at += padded;
    }
    if zero_blocks < 2 { bail!("base AP archive has no tar end marker") }
    let mut tail = vec![0; BUFFER];
    while at < tar_size {
        let count = tail.len().min((tar_size - at) as usize); input.read_exact(&mut tail[..count])?;
        if tail[..count].iter().any(|&byte| byte != 0) { bail!("non-zero data after tar end marker") }
        at += count as u64;
    }
    let missing = selected.difference(&seen).cloned().collect::<Vec<_>>();
    if !missing.is_empty() { bail!("base AP archive is missing replacement targets: {missing:?}") }
    if let Some((name, data)) = plain {
        if !seen.contains(&name) {
            if paths.contains(&safe_path(&name)?) { bail!("plain member path conflicts with an existing member: {name}") }
            output.plain(&plain_header(&name, data.len() as u64)?, &data)?;
        }
    }
    output.finish()?;
    Ok(Staged { temp: temporary, output: options.output, members: emitted, force: options.force })
}
