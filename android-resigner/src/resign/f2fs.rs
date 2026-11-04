use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};

use super::{blob::{self, Blob}, codesigner, crypto::Keys};

const BLOCK: u64 = 4096;
const SUPER_OFFSET: u64 = 1024;
const MAGIC: u32 = 0xf2f5_2010;
const NODE_FOOTER: usize = 4072;
const MAX_FIRMWARE: u64 = 512 << 20;
const CHECKPOINT_BYTES: usize = 192;
const NAT_ENTRY_BYTES: usize = 9;
const NAT_ENTRIES_PER_BLOCK: u32 = 455;
const SUMMARY_JOURNAL: usize = 512 * 7;

fn le16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(data.get(at..at + 2).context("truncated F2FS u16")?.try_into().unwrap()))
}

fn le32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated F2FS u32")?.try_into().unwrap()))
}

fn le64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(data.get(at..at + 8).context("truncated F2FS u64")?.try_into().unwrap()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct File { nid: u32, node: u64, data: u64, size: u64, name: String }

#[derive(Clone, Copy)]
struct Geometry { main: u64, end: u64 }

struct Layout {
    geometry: Geometry,
    nat_block: u64,
    nat_blocks: u32,
    blocks_per_segment: u32,
    nat_bitmap: Vec<u8>,
    nat_journal: BTreeMap<u32, (u32, u32)>,
}

fn crc32(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1)); }
    }
    crc
}

fn checkpoint_crc(block: &[u8]) -> Result<bool> {
    let at = le32(block, 164)? as usize;
    if !(CHECKPOINT_BYTES..=4092).contains(&at) { return Ok(false) }
    let mut crc = crc32(MAGIC, &block[..at]);
    if at < 4092 { crc = crc32(crc, &block[at + 4..4096]); }
    Ok(crc == le32(block, at)?)
}

#[derive(Clone)]
struct Checkpoint { start: u32, version: u64, block: Vec<u8> }

fn checkpoint_at(source: &Blob, start: u32, blocks_per_segment: u32) -> Result<Option<Checkpoint>> {
    let mut first = vec![0; BLOCK as usize]; source.read_exact_at(start as u64 * BLOCK, &mut first)?;
    if !checkpoint_crc(&first)? { return Ok(None) }
    let total = le32(&first, 136)?;
    if total == 0 || total > blocks_per_segment { return Ok(None) }
    let mut last = vec![0; BLOCK as usize]; source.read_exact_at((start + total - 1) as u64 * BLOCK, &mut last)?;
    if !checkpoint_crc(&last)? || le64(&first, 0)? != le64(&last, 0)? { return Ok(None) }
    Ok(Some(Checkpoint { start, version: le64(&first, 0)?, block: first }))
}

fn newer(left: u64, right: u64) -> bool { left != right && left.wrapping_sub(right) < 1 << 63 }

fn active_checkpoint(source: &Blob, cp_block: u32, blocks_per_segment: u32) -> Result<Checkpoint> {
    let first = checkpoint_at(source, cp_block, blocks_per_segment)?;
    let second = checkpoint_at(source, cp_block.checked_add(blocks_per_segment).context("F2FS checkpoint offset overflow")?, blocks_per_segment)?;
    match (first, second) {
        (Some(a), Some(b)) => Ok(if newer(b.version, a.version) { b } else { a }),
        (Some(value), None) | (None, Some(value)) => Ok(value),
        (None, None) => bail!("F2FS has no valid checkpoint pack"),
    }
}

fn layout(source: &Blob) -> Result<Option<Layout>> {
    if source.len()? < SUPER_OFFSET + 128 { return Ok(None) }
    let mut superblock = [0; 128]; source.read_exact_at(SUPER_OFFSET, &mut superblock)?;
    if le32(&superblock, 0)? != MAGIC { return Ok(None) }
    if le32(&superblock, 16)? != 12 { bail!("unsupported F2FS block size") }
    let blocks_per_segment = 1u32.checked_shl(le32(&superblock, 20)?).context("invalid F2FS segment geometry")?;
    let main = (le32(&superblock, 92)? as u64).checked_mul(BLOCK).context("F2FS main offset overflow")?;
    let blocks = (le32(&superblock, 68)? as u64).checked_mul(blocks_per_segment as u64).context("F2FS main size overflow")?;
    let bytes = blocks.checked_mul(BLOCK).context("F2FS main size overflow")?;
    let source_len = source.len()?;
    let end = main.checked_add(bytes).filter(|&end| end <= source_len).context("F2FS main area exceeds image")?;
    let checkpoint = active_checkpoint(source, le32(&superblock, 76)?, blocks_per_segment)?;
    let flags = le32(&checkpoint.block, 132)?;
    if flags & 1 == 0 || flags & (0x4 | 0x400) != 0 { bail!("unsupported F2FS checkpoint layout flags {flags:#x}") }
    let sit_bytes = le32(&checkpoint.block, 156)? as usize;
    let nat_bytes = le32(&checkpoint.block, 160)? as usize;
    let nat_blocks = (le32(&superblock, 60)? / 2).checked_mul(blocks_per_segment).context("F2FS NAT geometry overflow")?;
    if nat_bytes != nat_blocks.div_ceil(8) as usize { bail!("inconsistent F2FS NAT bitmap size") }
    let bitmap_at = CHECKPOINT_BYTES.checked_add(sit_bytes).context("F2FS bitmap offset overflow")?;
    let bitmap_end = bitmap_at.checked_add(nat_bytes).filter(|&end| end <= 4092).context("F2FS NAT bitmap exceeds checkpoint")?;
    let nat_bitmap = checkpoint.block[bitmap_at..bitmap_end].to_vec();

    let total = le32(&checkpoint.block, 136)?;
    if total < 7 { bail!("F2FS checkpoint pack has no normal summary blocks") }
    let summary_block = checkpoint.start.checked_add(total - 7).context("F2FS summary offset overflow")?;
    let mut summary = vec![0; BLOCK as usize]; source.read_exact_at(summary_block as u64 * BLOCK, &mut summary)?;
    let count = le16(&summary, SUMMARY_JOURNAL)? as usize;
    let maximum = (4096 - 5 - SUMMARY_JOURNAL - 2) / 13;
    if count > maximum { bail!("invalid F2FS NAT journal entry count") }
    let mut nat_journal = BTreeMap::new();
    for index in 0..count {
        let at = SUMMARY_JOURNAL + 2 + index * 13;
        let nid = le32(&summary, at)?;
        let ino = le32(&summary, at + 5)?;
        let block = le32(&summary, at + 9)?;
        if nat_journal.insert(nid, (ino, block)).is_some() { bail!("duplicate F2FS NAT journal entry") }
    }
    Ok(Some(Layout {
        geometry: Geometry { main, end }, nat_block: le32(&superblock, 84)? as u64,
        nat_blocks, blocks_per_segment, nat_bitmap, nat_journal,
    }))
}

pub fn present(source: &Blob) -> Result<bool> { Ok(layout(source)?.is_some()) }

impl Layout {
    fn nat_entry(&self, source: &Blob, nid: u32, cache: &mut BTreeMap<u64, Vec<u8>>) -> Result<(u32, u32)> {
        if let Some(&entry) = self.nat_journal.get(&nid) { return Ok(entry) }
        let block_off = nid / NAT_ENTRIES_PER_BLOCK;
        if block_off >= self.nat_blocks { bail!("F2FS inode {nid:#x} exceeds NAT") }
        let segment = block_off / self.blocks_per_segment;
        let within = block_off % self.blocks_per_segment;
        let mut block = self.nat_block
            .checked_add((segment as u64) * (self.blocks_per_segment as u64) * 2)
            .and_then(|value| value.checked_add(within as u64)).context("F2FS NAT offset overflow")?;
        let bit = 1 << (7 - (block_off & 7));
        if self.nat_bitmap[block_off as usize / 8] & bit != 0 { block += self.blocks_per_segment as u64; }
        if !cache.contains_key(&block) {
            let mut data = vec![0; BLOCK as usize]; source.read_exact_at(block * BLOCK, &mut data)?; cache.insert(block, data);
        }
        let data = &cache[&block];
        let at = (nid % NAT_ENTRIES_PER_BLOCK) as usize * NAT_ENTRY_BYTES;
        Ok((le32(data, at + 1)?, le32(data, at + 5)?))
    }
}

fn inode(block: &[u8], node: u64, geometry: Geometry) -> Result<Option<File>> {
    let nid = le32(block, NODE_FOOTER)?;
    let ino = le32(block, NODE_FOOTER + 4)?;
    if nid < 3 || nid != ino || le16(block, 0)? & 0o170000 != 0o100000 { return Ok(None) }
    let size = le64(block, 16)?;
    if !(0x210..=MAX_FIRMWARE).contains(&size) { return Ok(None) }
    let inline = block[3];
    if inline & (0x02 | 0x80) != 0 { return Ok(None) }
    if le32(block, 80)? != 0 { return Ok(None) }
    let file_offset = le32(block, 348)?;
    let first = le32(block, 352)? as u64;
    let blocks = le32(block, 356)? as u64;
    if file_offset != 0 || first <= 1 || blocks == 0 || size > blocks.checked_mul(BLOCK).context("F2FS extent size overflow")? { return Ok(None) }
    let data = first.checked_mul(BLOCK).context("F2FS extent offset overflow")?;
    if data < geometry.main || data.checked_add(size).filter(|&end| end <= geometry.end).is_none() { return Ok(None) }
    let len = le32(block, 88)? as usize;
    let name = block.get(92..92 + len.min(255)).and_then(|value| std::str::from_utf8(value).ok())
        .filter(|value| !value.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("inode-{nid:x}"));
    Ok(Some(File { nid, node, data, size, name }))
}

fn files(source: &Blob) -> Result<Vec<File>> {
    let layout = layout(source)?.context("not an F2FS image")?;
    let geometry = layout.geometry;
    let mut scanned = Vec::new();
    let mut buffer = vec![0; 4 << 20];
    let mut at = geometry.main;
    while at < geometry.end {
        crate::cancel::check()?;
        let count = buffer.len().min((geometry.end - at) as usize);
        source.read_exact_at(at, &mut buffer[..count])?;
        for (index, block) in buffer[..count].chunks_exact(BLOCK as usize).enumerate() {
            let node = at + index as u64 * BLOCK;
            let Some(file) = inode(block, node, geometry)? else { continue };
            scanned.push(file);
        }
        at += count as u64;
    }
    let mut cache = BTreeMap::new(); let mut current = BTreeMap::<u32, File>::new();
    for file in scanned {
        let (ino, block) = layout.nat_entry(source, file.nid, &mut cache)?;
        if ino != file.nid || block as u64 * BLOCK != file.node { continue }
        let nid = file.nid;
        if current.insert(nid, file).is_some() { bail!("multiple live F2FS inode blocks for {nid:#x}") }
    }
    Ok(current.into_values().collect())
}

fn candidates(source: &Blob) -> Result<Vec<File>> {
    let mut found = Vec::new();
    for file in files(source)? {
        let mut tail = [0; 0x210];
        source.read_exact_at(file.data + file.size - tail.len() as u64, &mut tail)?;
        if codesigner::firmware_key_type(&tail).is_some() { found.push(file) }
    }
    found.sort_by_key(|file| (file.data, file.nid));
    for pair in found.windows(2) {
        if pair[0].data + pair[0].size > pair[1].data { bail!("overlapping signed F2FS file extents") }
    }
    Ok(found)
}

pub fn resign(source: Blob, keys: &Keys, description: &str) -> Result<(Blob, usize)> {
    let before = candidates(&source)?;
    let mut changes = Vec::with_capacity(before.len());
    for file in &before {
        let mut data = vec![0; file.size as usize]; source.read_exact_at(file.data, &mut data)?;
        let original = data.clone();
        let key_type = codesigner::sign_firmware(&mut data, keys, &format!("{description}:inode-{:#x}", file.nid))?;
        let footer = data.len() - 0x210; let signature = data.len() - 0x200;
        if original.iter().zip(&data).enumerate().any(|(at, (old, new))| old != new && !((footer + 12..footer + 16).contains(&at) || (signature..signature + 136).contains(&at))) {
            bail!("{description}: CodeSigner update escaped the existing footer for inode {:#x}", file.nid)
        }
        codesigner::verify_firmware(&data, keys, &format!("{description}:inode-{:#x}", file.nid))?;
        eprintln!("CodeSigned {description}:{} ({})", file.name, if key_type == 0 { "TEE" } else { "REE" });
        changes.push((file.data, data));
    }
    let output = blob::patch(source, changes)?;
    let after = candidates(&output)?;
    if before != after { bail!("{description}: signed F2FS firmware set changed during rebuild") }
    for file in &after {
        let mut data = vec![0; file.size as usize]; output.read_exact_at(file.data, &mut data)?;
        codesigner::verify_firmware(&data, keys, &format!("{description}:inode-{:#x}", file.nid))?;
    }
    Ok((output, after.len()))
}
