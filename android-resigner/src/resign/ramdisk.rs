use std::{
    collections::BTreeSet,
    io::{Read, Write},
};

use anyhow::{bail, Context, Result};
use lz4::block::{self, CompressionMode};

use super::{codesigner, config::Ramdisk, crypto::Keys};

const LEGACY: &[u8] = b"\x02\x21\x4c\x18";
const LEGACY_BLOCK: usize = 8 << 20;
const MAX_RAMDISK: usize = 512 << 20;

fn limited(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.by_ref().take(MAX_RAMDISK as u64 + 1).read_to_end(&mut output)?;
    if output.len() > MAX_RAMDISK { bail!("ramdisk expands past {MAX_RAMDISK} bytes") }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Compression {
    Gzip,
    Lz4Legacy,
    Lz4Frame,
    Zstd,
    Xz,
    None,
}

fn decompress(data: &[u8]) -> Result<(Vec<u8>, Compression)> {
    let mut out = Vec::new();
    if data.starts_with(b"\x1f\x8b") {
        out = limited(flate2::read::MultiGzDecoder::new(data))?;
        return Ok((out, Compression::Gzip));
    }
    if data.starts_with(LEGACY) {
        let mut at = LEGACY.len();
        while at < data.len() {
            let size = u32::from_le_bytes(
                data.get(at..at + 4)
                    .context("truncated legacy LZ4 block size")?
                    .try_into()
                    .unwrap(),
            ) as usize;
            at += 4;
            if size == 0 {
                bail!("invalid empty legacy LZ4 block")
            }
            let encoded = data
                .get(at..at + size)
                .context("truncated legacy LZ4 block")?;
            at += size;
            let decoded = block::decompress(encoded, Some(LEGACY_BLOCK as i32)).context("invalid legacy LZ4 block")?;
            if out.len().checked_add(decoded.len()).is_none_or(|size| size > MAX_RAMDISK) { bail!("ramdisk expands past {MAX_RAMDISK} bytes") }
            out.extend(decoded);
        }
        return Ok((out, Compression::Lz4Legacy));
    }
    if data.starts_with(b"\x04\x22\x4d\x18") {
        out = limited(lz4::Decoder::new(data)?)?;
        return Ok((out, Compression::Lz4Frame));
    }
    if data.starts_with(b"\x28\xb5\x2f\xfd") {
        return Ok((limited(zstd::stream::read::Decoder::new(data)?)?, Compression::Zstd));
    }
    if data.starts_with(b"\xfd7zXZ\0") {
        out = limited(xz2::read::XzDecoder::new(data))?;
        return Ok((out, Compression::Xz));
    }
    if matches!(data.get(..6), Some(b"070701" | b"070702")) {
        if data.len() > MAX_RAMDISK { bail!("ramdisk exceeds {MAX_RAMDISK} bytes") }
        return Ok((data.to_vec(), Compression::None));
    }
    bail!("unsupported ramdisk compression")
}

fn compress(data: &[u8], kind: Compression) -> Result<Vec<u8>> {
    match kind {
        Compression::Gzip => {
            let mut encoder = flate2::GzBuilder::new()
                .mtime(0)
                .write(Vec::new(), flate2::Compression::best());
            encoder.write_all(data)?;
            Ok(encoder.finish()?)
        }
        Compression::Lz4Legacy => {
            let mut out = LEGACY.to_vec();
            for piece in data.chunks(LEGACY_BLOCK) {
                let encoded = block::compress(
                    piece,
                    Some(CompressionMode::HIGHCOMPRESSION(12)),
                    false,
                )?;
                out.extend_from_slice(
                    &u32::try_from(encoded.len())
                        .context("legacy LZ4 block is too large")?
                        .to_le_bytes(),
                );
                out.extend_from_slice(&encoded);
            }
            Ok(out)
        }
        Compression::Lz4Frame => {
            let mut builder = lz4::EncoderBuilder::new();
            builder.level(12);
            let mut encoder = builder.build(Vec::new())?;
            encoder.write_all(data)?;
            let (out, result) = encoder.finish();
            result?;
            Ok(out)
        }
        Compression::Zstd => Ok(zstd::stream::encode_all(data, 19)?),
        Compression::Xz => {
            let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 9);
            encoder.write_all(data)?;
            Ok(encoder.finish()?)
        }
        Compression::None => Ok(data.to_vec()),
    }
}

fn field(data: &[u8], at: usize) -> Result<usize> {
    let value = data.get(at..at + 8).context("truncated newc field")?;
    usize::from_str_radix(
        std::str::from_utf8(value).context("non-ASCII newc field")?,
        16,
    )
    .context("invalid newc field")
}

fn align_from(value: usize, base: usize) -> Result<usize> {
    let relative = value.checked_sub(base).context("newc offset before archive")?;
    base.checked_add(
        relative
            .checked_add(3)
            .context("newc alignment overflow")?
            & !3,
    )
    .context("newc alignment overflow")
}

fn normalized_name(raw: &[u8]) -> Option<String> {
    let mut name = std::str::from_utf8(raw).ok()?;
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    (!name.is_empty() && !name.starts_with('/') && !name.split('/').any(|part| part == ".."))
        .then(|| name.to_owned())
}

#[derive(Clone, Debug)]
struct Entry {
    header: usize,
    data: std::ops::Range<usize>,
    name: Option<String>,
    crc: bool,
    regular: bool,
}

fn entries(data: &[u8]) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut archives = 0usize;
    while at < data.len() {
        while data.get(at) == Some(&0) {
            at += 1;
        }
        if at == data.len() {
            break;
        }
        let base = at;
        if !matches!(data.get(at..at + 6), Some(b"070701" | b"070702")) {
            bail!("non-zero data outside a structural newc archive at {at:#x}")
        }
        archives += 1;
        loop {
            let magic = data
                .get(at..at + 6)
                .context("truncated newc header magic")?;
            if !matches!(magic, b"070701" | b"070702") {
                bail!("invalid newc entry magic at {at:#x}")
            }
            data.get(at..at + NEWC_HEADER)
                .context("truncated newc header")?;
            let mode = field(data, at + 14)?;
            let size = field(data, at + 54)?;
            let name_size = field(data, at + 94)?;
            let name_at = at
                .checked_add(NEWC_HEADER)
                .context("newc name offset overflow")?;
            let name_end = name_at
                .checked_add(name_size)
                .context("newc name overflow")?;
            if name_size == 0 || data.get(name_end - 1) != Some(&0) {
                bail!("invalid newc filename at {at:#x}")
            }
            let data_at = align_from(name_end, base)?;
            let data_end = data_at.checked_add(size).context("newc data overflow")?;
            let next = align_from(data_end, base)?;
            if next > data.len() {
                bail!("truncated newc entry at {at:#x}")
            }
            let raw_name = &data[name_at..name_end - 1];
            if raw_name == b"TRAILER!!!" {
                if size != 0 {
                    bail!("newc TRAILER!!! entry has data")
                }
                at = next;
                break;
            }
            out.push(Entry {
                header: at,
                data: data_at..data_end,
                name: normalized_name(raw_name),
                crc: magic == b"070702",
                regular: mode & 0o170000 == 0o100000,
            });
            at = next;
        }
    }
    if archives == 0 {
        bail!("ramdisk contains no structural newc archive")
    }
    Ok(out)
}

pub(super) fn logical_fstab(data: &[u8]) -> Result<BTreeSet<String>> {
    let (archive, _) = decompress(data)?;
    let mut output = BTreeSet::new();
    for entry in entries(&archive)? {
        let Some(name) = entry.name else { continue };
        if !entry.regular || !name.rsplit('/').next().is_some_and(|name| name.starts_with("fstab")) { continue }
        let text = std::str::from_utf8(&archive[entry.data]).with_context(|| format!("{name} is not UTF-8"))?;
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 { bail!("invalid fstab line in {name}") }
            if fields[4..].iter().flat_map(|field| field.split(',')).any(|flag| flag == "logical") {
                let part = fields[0];
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) { bail!("invalid logical partition in {name}") }
                output.insert(part.to_owned());
            }
        }
    }
    Ok(output)
}

const NEWC_HEADER: usize = 110;

pub(super) struct PatchResult {
    pub data: Vec<u8>,
    pub signed: usize,
    pub found: BTreeSet<String>,
}

fn patch_newc(
    mut data: Vec<u8>,
    rules: &Ramdisk,
    keys: &Keys,
    description: &str,
) -> Result<PatchResult> {
    let wanted = rules
        .firmware
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let list = entries(&data)?;
    let mut found = BTreeSet::new();
    let mut changed = Vec::new();

    for (index, entry) in list.iter().enumerate() {
        let Some(name) = entry.name.as_ref() else {
            continue;
        };
        let configured = wanted.contains(name.as_str());
        if !entry.regular {
            continue;
        }
        let Some(_key_type) = codesigner::firmware_key_type(&data[entry.data.clone()]) else {
            continue;
        };
        if !configured && !rules.discover_firmware {
            continue;
        }

        let key_type = codesigner::sign_firmware(
            &mut data[entry.data.clone()],
            keys,
            &format!("{description}:{name}"),
        )?;
        if entry.crc {
            let checksum = data[entry.data.clone()]
                .iter()
                .fold(0u32, |sum, &byte| sum.wrapping_add(byte as u32));
            data[entry.header + 102..entry.header + 110]
                .copy_from_slice(format!("{checksum:08x}").as_bytes());
        }
        if configured {
            found.insert(name.clone());
        }
        changed.push((index, key_type));
        eprintln!("CodeSigned {description}:{name} ({})", if key_type == 0 { "TEE" } else { "REE" });
    }

    let audited = entries(&data)?;
    if audited.len() != list.len() {
        bail!("{description}: newc entry set changed while signing firmware")
    }
    for (index, key_type) in &changed {
        let entry = &audited[*index];
        let name = entry.name.as_deref().unwrap_or("<non-UTF8>");
        let actual = codesigner::verify_firmware(
            &data[entry.data.clone()],
            keys,
            &format!("{description}:{name}"),
        )?;
        if actual != *key_type {
            bail!("{description}:{name}: CodeSigner key mode changed during rebuild")
        }
    }

    Ok(PatchResult {
        data,
        signed: changed.len(),
        found,
    })
}

pub(super) fn finish(
    rules: &Ramdisk,
    found: &BTreeSet<String>,
    description: &str,
) -> Result<()> {
    let missing = rules
        .firmware
        .iter()
        .filter(|path| !found.contains(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if rules.require_all && !missing.is_empty() {
        bail!(
            "missing required signed ramdisk firmware in {description}: {}",
            missing.join(", ")
        )
    }
    Ok(())
}

pub(super) fn patch_fragment(
    data: &[u8],
    rules: &Ramdisk,
    keys: &Keys,
    description: &str,
) -> Result<PatchResult> {
    let (archive, compression) = decompress(data)?;
    let mut result = patch_newc(archive, rules, keys, description)?;
    if result.signed == 0 {
        result.data = data.to_vec();
    } else {
        let archive = result.data;
        let encoded = compress(&archive, compression)?;
        let (decoded, after) = decompress(&encoded)?;
        if after != compression {
            bail!("{description}: ramdisk compression changed during rebuild")
        }
        if decoded != archive {
            bail!("{description}: ramdisk compression round trip changed the newc archive")
        }
        result.data = encoded;
    }
    Ok(result)
}

pub(super) fn patch(
    data: &[u8],
    rules: &Ramdisk,
    keys: &Keys,
    description: &str,
) -> Result<PatchResult> {
    let result = patch_fragment(data, rules, keys, description)?;
    finish(rules, &result.found, description)?;
    Ok(result)
}
