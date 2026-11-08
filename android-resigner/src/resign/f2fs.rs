use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use lz4::block::{self, CompressionMode};

use super::{blob::{self, Blob}, codesigner, crypto::Keys};
use crate::par;

const BLOCK: u64 = 4096;
const SUPER_OFFSET: u64 = 1024;
const MAGIC: u32 = 0xf2f5_2010;
const NODE_FOOTER: usize = 4072;
const MAX_FIRMWARE: u64 = 512 << 20;
const CHECKPOINT_BYTES: usize = 192;
const NAT_ENTRY_BYTES: usize = 9;
const NAT_ENTRIES_PER_BLOCK: u32 = 455;
const SUMMARY_JOURNAL: usize = 512 * 7;
const INODE_ADDR: usize = 360;
const INODE_NIDS: usize = NODE_FOOTER - 20;
const NODE_ADDRS: usize = NODE_FOOTER / 4;
const INLINE_XATTR: u8 = 1;
const EXTRA_ATTR: u8 = 0x20;
const COMPRESS_FLAG: u32 = 4;
const COMPRESS_ADDR: u32 = u32::MAX - 1;
const NEW_ADDR: u32 = u32::MAX;
const COMPRESS_HEADER: usize = 24;

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
struct Clustered { algorithm: u8, log: u8, flags: u16, blocks: Vec<u32>, nids: [u32; 5] }

#[derive(Clone, Debug, Eq, PartialEq)]
enum FileData { Flat(u64), Clustered(Clustered) }

#[derive(Clone, Debug, Eq, PartialEq)]
struct File { nid: u32, node: u64, data: FileData, size: u64, name: String }

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate { file: File, ranges: Vec<codesigner::FirmwareRange>, data: Vec<u8> }

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

    fn node(&self, source: &Blob, nid: u32, ino: u32, nat: &mut BTreeMap<u64, Vec<u8>>,
            nodes: &mut BTreeMap<u32, Vec<u8>>) -> Result<Vec<u8>> {
        if let Some(data) = nodes.get(&nid) { return Ok(data.clone()) }
        let (owner, block) = self.nat_entry(source, nid, nat)?;
        if owner != ino { bail!("F2FS node {nid:#x} belongs to inode {owner:#x}, expected {ino:#x}") }
        let at = block as u64 * BLOCK;
        if at < self.geometry.main || at.checked_add(BLOCK).is_none_or(|end| end > self.geometry.end) {
            bail!("F2FS node {nid:#x} is outside the main area")
        }
        let mut data = vec![0; BLOCK as usize]; source.read_exact_at(at, &mut data)?;
        if le32(&data, NODE_FOOTER)? != nid || le32(&data, NODE_FOOTER + 4)? != ino {
            bail!("F2FS node {nid:#x} footer mismatch")
        }
        nodes.insert(nid, data.clone());
        Ok(data)
    }

    fn append_node(&self, source: &Blob, nid: u32, ino: u32, depth: u8, cluster: usize, wanted: usize,
                   out: &mut Vec<u32>, nat: &mut BTreeMap<u64, Vec<u8>>,
                   nodes: &mut BTreeMap<u32, Vec<u8>>) -> Result<()> {
        if out.len() >= wanted { return Ok(()) }
        let leaf = NODE_ADDRS & !(cluster - 1);
        let capacity = NODE_ADDRS.checked_pow(depth as u32).and_then(|count| count.checked_mul(leaf))
            .context("F2FS node capacity overflow")?;
        if nid == 0 {
            out.resize(wanted.min(out.len().checked_add(capacity).context("F2FS address count overflow")?), 0);
            return Ok(())
        }
        let data = self.node(source, nid, ino, nat, nodes)?;
        if depth == 0 {
            let take = (wanted - out.len()).min(leaf);
            for at in (0..take * 4).step_by(4) { out.push(le32(&data, at)?); }
        } else {
            for at in (0..NODE_FOOTER).step_by(4) {
                self.append_node(source, le32(&data, at)?, ino, depth - 1, cluster, wanted, out, nat, nodes)?;
                if out.len() == wanted { break }
            }
        }
        Ok(())
    }

    fn resolve(&self, source: &Blob, file: &mut File, nat: &mut BTreeMap<u64, Vec<u8>>,
               nodes: &mut BTreeMap<u32, Vec<u8>>) -> Result<()> {
        let FileData::Clustered(data) = &mut file.data else { return Ok(()) };
        let cluster = 1usize.checked_shl(data.log.into()).context("invalid F2FS cluster size")?;
        let pages = usize::try_from(file.size.div_ceil(BLOCK)).context("F2FS file page count overflow")?;
        let wanted = pages.checked_add(cluster - 1).map(|value| value & !(cluster - 1)).context("F2FS cluster count overflow")?;
        data.blocks.truncate(data.blocks.len() & !(cluster - 1));
        data.blocks.truncate(wanted);
        for (index, depth) in [(0, 0), (1, 0), (2, 1), (3, 1), (4, 2)] {
            self.append_node(source, data.nids[index], file.nid, depth, cluster, wanted, &mut data.blocks, nat, nodes)?;
        }
        if data.blocks.len() != wanted { bail!("F2FS inode {:#x} has {} of {wanted} data addresses", file.nid, data.blocks.len()) }
        Ok(())
    }
}

fn inode(block: &[u8], node: u64, geometry: Geometry) -> Result<Option<File>> {
    let nid = le32(block, NODE_FOOTER)?;
    let ino = le32(block, NODE_FOOTER + 4)?;
    if nid < 3 || nid != ino || le16(block, 0)? & 0o170000 != 0o100000 { return Ok(None) }
    let size = le64(block, 16)?;
    if !(0x210..=MAX_FIRMWARE).contains(&size) { return Ok(None) }
    let inline = block[3];
    let len = le32(block, 88)? as usize;
    let name = block.get(92..92 + len.min(255)).and_then(|value| std::str::from_utf8(value).ok())
        .filter(|value| !value.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("inode-{nid:x}"));
    if inline & 0x02 != 0 { return Ok(None) }
    let data = if le32(block, 80)? & COMPRESS_FLAG != 0 {
        if inline & EXTRA_ATTR == 0 { bail!("compressed F2FS inode {nid:#x} has no extra attributes") }
        let extra = le16(block, INODE_ADDR)? as usize;
        if extra < 36 || extra & 3 != 0 { bail!("invalid compressed F2FS extra size {extra}") }
        let xattrs = if inline & INLINE_XATTR == 0 { 0 } else {
            let value = le16(block, INODE_ADDR + 2)? as usize; if value == 0 { 50 } else { value }
        };
        let start = INODE_ADDR.checked_add(extra).context("F2FS inode address overflow")?;
        let end = INODE_NIDS.checked_sub(xattrs.checked_mul(4).context("F2FS inline xattr overflow")?)
            .filter(|&end| start <= end).context("F2FS inode addresses overlap xattrs")?;
        let mut blocks = Vec::with_capacity((end - start) / 4);
        for at in (start..end).step_by(4) { blocks.push(le32(block, at)?); }
        let mut nids = [0; 5];
        for (index, at) in (INODE_NIDS..NODE_FOOTER).step_by(4).enumerate() { nids[index] = le32(block, at)?; }
        let algorithm = block[INODE_ADDR + 32];
        let log = block[INODE_ADDR + 33];
        if !(2..=8).contains(&log) { bail!("invalid F2FS cluster log {log}") }
        FileData::Clustered(Clustered { algorithm, log, flags: le16(block, INODE_ADDR + 34)?, blocks, nids })
    } else {
        if inline & 0x80 != 0 || le32(block, 80)? != 0 { return Ok(None) }
        let file_offset = le32(block, 348)?;
        let first = le32(block, 352)? as u64;
        let blocks = le32(block, 356)? as u64;
        if file_offset != 0 || first <= 1 || blocks == 0 || size > blocks.checked_mul(BLOCK).context("F2FS extent size overflow")? { return Ok(None) }
        let at = first.checked_mul(BLOCK).context("F2FS extent offset overflow")?;
        if at < geometry.main || at.checked_add(size).filter(|&end| end <= geometry.end).is_none() { return Ok(None) }
        FileData::Flat(at)
    };
    Ok(Some(File { nid, node, data, size, name }))
}

fn files(source: &Blob) -> Result<(Geometry, Vec<File>)> {
    let layout = layout(source)?.context("not an F2FS image")?;
    let geometry = layout.geometry;
    let chunk = 1u64 << 20;
    let mut scanned = Vec::new();
    par::ordered((geometry.end - geometry.main).div_ceil(chunk) as usize, |index| -> Result<Vec<File>> {
        let at = geometry.main + index as u64 * chunk;
        let mut buffer = vec![0; chunk.min(geometry.end - at) as usize];
        source.read_exact_at(at, &mut buffer)?;
        buffer.chunks_exact(BLOCK as usize).enumerate()
            .filter_map(|(index, block)| inode(block, at + index as u64 * BLOCK, geometry).transpose()).collect()
    }, |files| { scanned.extend(files); Ok(()) })?;
    let mut cache = BTreeMap::new(); let mut current = BTreeMap::<u32, File>::new();
    for file in scanned {
        let (ino, block) = layout.nat_entry(source, file.nid, &mut cache)?;
        if ino != file.nid || block as u64 * BLOCK != file.node { continue }
        let nid = file.nid;
        if current.insert(nid, file).is_some() { bail!("multiple live F2FS inode blocks for {nid:#x}") }
    }
    let mut nodes = BTreeMap::new();
    let mut files = current.into_values().collect::<Vec<_>>();
    for file in &mut files { layout.resolve(source, file, &mut cache, &mut nodes)?; }
    Ok((geometry, files))
}

fn read_block(source: &Blob, geometry: Geometry, block: u32) -> Result<Vec<u8>> {
    if matches!(block, 0 | NEW_ADDR | COMPRESS_ADDR) { bail!("invalid F2FS physical block {block:#x}") }
    let at = block as u64 * BLOCK;
    if at < geometry.main || at.checked_add(BLOCK).is_none_or(|end| end > geometry.end) {
        bail!("F2FS data block {block:#x} is outside the main area")
    }
    let mut data = vec![0; BLOCK as usize]; source.read_exact_at(at, &mut data)?; Ok(data)
}

fn cluster(source: &Blob, geometry: Geometry, data: &Clustered, index: usize) -> Result<Vec<u8>> {
    let count = 1usize << data.log;
    let start = index.checked_mul(count).context("F2FS cluster offset overflow")?;
    let slots = data.blocks.get(start..start + count).context("F2FS cluster exceeds address map")?;
    if slots[0] != COMPRESS_ADDR {
        let mut out = Vec::with_capacity(count * BLOCK as usize);
        for &block in slots {
            if block == 0 { out.extend_from_slice(&[0; BLOCK as usize]); }
            else { out.extend_from_slice(&read_block(source, geometry, block)?); }
        }
        return Ok(out)
    }
    if data.algorithm != 1 { bail!("unsupported F2FS compression algorithm {}", data.algorithm) }
    let mut packed = Vec::new(); let mut ended = false;
    for &block in &slots[1..] {
        if block == 0 { ended = true; continue }
        if ended || matches!(block, NEW_ADDR | COMPRESS_ADDR) { bail!("invalid F2FS compressed cluster map") }
        packed.extend_from_slice(&read_block(source, geometry, block)?);
    }
    if packed.len() < COMPRESS_HEADER { bail!("empty F2FS compressed cluster") }
    let size = le32(&packed, 0)? as usize;
    let end = COMPRESS_HEADER.checked_add(size).filter(|&end| end <= packed.len()).context("F2FS compressed data exceeds its blocks")?;
    if data.flags & 1 != 0 && le32(&packed, 4)? != crc32(MAGIC, &packed[COMPRESS_HEADER..end]) {
        bail!("invalid F2FS compressed cluster checksum")
    }
    let expected = count.checked_mul(BLOCK as usize).context("F2FS cluster size overflow")?;
    let out = block::decompress(&packed[COMPRESS_HEADER..end], Some(expected as i32))?;
    if out.len() != expected { bail!("invalid F2FS decompressed cluster size") }
    Ok(out)
}

fn read_file(source: &Blob, geometry: Geometry, file: &File) -> Result<Vec<u8>> {
    match &file.data {
        FileData::Flat(at) => {
            let mut out = vec![0; file.size as usize]; source.read_exact_at(*at, &mut out)?; Ok(out)
        }
        FileData::Clustered(data) => {
            let bytes = (BLOCK as usize) << data.log;
            let count = (file.size as usize).div_ceil(bytes);
            let mut out = Vec::with_capacity(count * bytes);
            for index in 0..count { out.extend_from_slice(&cluster(source, geometry, data, index)?); }
            out.truncate(file.size as usize); Ok(out)
        }
    }
}

fn file_range(source: &Blob, geometry: Geometry, file: &File, start: usize, len: usize) -> Result<Vec<u8>> {
    let end = start.checked_add(len).filter(|&end| end <= file.size as usize).context("F2FS file range exceeds file")?;
    match &file.data {
        FileData::Flat(at) => {
            let mut out = vec![0; len]; source.read_exact_at(*at + start as u64, &mut out)?; Ok(out)
        }
        FileData::Clustered(data) => {
            let bytes = (BLOCK as usize) << data.log;
            let first = start / bytes; let last = (end - 1) / bytes;
            let mut out = Vec::with_capacity((last - first + 1) * bytes);
            for index in first..=last { out.extend_from_slice(&cluster(source, geometry, data, index)?); }
            let at = start - first * bytes; Ok(out[at..at + len].to_vec())
        }
    }
}

fn encode_cluster(raw: &[u8], capacity: usize, flags: u16) -> Result<Vec<u8>> {
    let encoded = block::compress(raw, Some(CompressionMode::HIGHCOMPRESSION(12)), false)?;
    let end = COMPRESS_HEADER.checked_add(encoded.len()).filter(|&end| end <= capacity)
        .context("updated F2FS compressed cluster no longer fits")?;
    let mut out = vec![0; capacity];
    out[..4].copy_from_slice(&u32::try_from(encoded.len()).context("F2FS compressed size overflow")?.to_le_bytes());
    if flags & 1 != 0 { out[4..8].copy_from_slice(&crc32(MAGIC, &encoded).to_le_bytes()); }
    out[COMPRESS_HEADER..end].copy_from_slice(&encoded);
    let decoded = block::decompress(&out[COMPRESS_HEADER..end], Some(raw.len() as i32))?;
    if decoded != raw { bail!("F2FS recompression verification failed") }
    Ok(out)
}

fn rewrite_file(source: &Blob, geometry: Geometry, file: &File, old: &[u8], new: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    if old.len() != new.len() || old.len() != file.size as usize { bail!("F2FS replacement size changed") }
    let data = match &file.data {
        FileData::Flat(at) => return Ok(if old == new { Vec::new() } else { vec![(*at, new.to_vec())] }),
        FileData::Clustered(data) => data,
    };
    let count = 1usize << data.log; let bytes = count * BLOCK as usize;
    let clusters = old.len().div_ceil(bytes); let mut changes = Vec::new();
    for index in 0..clusters {
        let mut raw = cluster(source, geometry, data, index)?;
        let at = index * bytes; let len = (old.len() - at).min(bytes);
        if old[at..at + len] == new[at..at + len] { continue }
        if raw[..len] != old[at..at + len] { bail!("F2FS decoded file changed during rewrite") }
        raw[..len].copy_from_slice(&new[at..at + len]);
        let slots = &data.blocks[index * count..(index + 1) * count];
        if slots[0] == COMPRESS_ADDR {
            let blocks = slots[1..].iter().take_while(|&&block| block != 0).copied().collect::<Vec<_>>();
            let packed = encode_cluster(&raw, blocks.len() * BLOCK as usize, data.flags)?;
            for (block, page) in blocks.iter().zip(packed.chunks_exact(BLOCK as usize)) {
                read_block(source, geometry, *block)?;
                changes.push((*block as u64 * BLOCK, page.to_vec()));
            }
        } else {
            for (&block, page) in slots.iter().zip(raw.chunks_exact(BLOCK as usize)) {
                if block == 0 {
                    if page.iter().any(|&byte| byte != 0) { bail!("F2FS rewrite would allocate a sparse block") }
                } else {
                    read_block(source, geometry, block)?;
                    changes.push((block as u64 * BLOCK, page.to_vec()));
                }
            }
        }
    }
    Ok(changes)
}

fn candidates(source: &Blob) -> Result<(Geometry, Vec<Candidate>)> {
    let (geometry, files) = files(source)?;
    let mut found = Vec::new();
    par::ordered(files.len(), |index| -> Result<Option<Candidate>> {
        crate::cancel::check()?;
        let file = &files[index];
        let head = file_range(source, geometry, file, 0, 4)?;
        let tail = file_range(source, geometry, file, file.size as usize - 0x210, 0x210)?;
        if head != b"\x7fELF" && codesigner::firmware_key_type(&tail).is_none() { return Ok(None) }
        let data = read_file(source, geometry, file)?;
        let ranges = codesigner::firmware_ranges(&data)?;
        let data = if ranges.iter().any(|range| range.key_type <= 1) { data } else { Vec::new() };
        Ok((!ranges.is_empty()).then(|| Candidate { file: file.clone(), ranges, data }))
    }, |item| { found.extend(item); Ok(()) })?;
    found.sort_by_key(|item| (item.file.node, item.file.nid));
    Ok((geometry, found))
}

fn check_blocks(files: &[Candidate]) -> Result<()> {
    let mut used = BTreeMap::<u32, (u32, usize)>::new();
    let mut inodes = BTreeMap::<u32, (&FileData, u64, u64)>::new();
    for item in files {
        let file = &item.file;
        if let Some(&(data, node, size)) = inodes.get(&file.nid) {
            if data != &file.data || node != file.node || size != file.size {
                bail!("conflicting F2FS candidate inode {:#x}", file.nid)
            }
            continue
        }
        inodes.insert(file.nid, (&file.data, file.node, file.size));
        match &file.data {
            FileData::Flat(at) => {
                let first = u32::try_from(*at / BLOCK).context("F2FS block number overflow")?;
                let count = usize::try_from(file.size.div_ceil(BLOCK)).context("F2FS block count overflow")?;
                for slot in 0..count {
                    let block = first.checked_add(u32::try_from(slot).context("F2FS block offset overflow")?)
                        .context("F2FS block number overflow")?;
                    if let Some((nid, old)) = used.insert(block, (file.nid, slot)) {
                        bail!("F2FS data block {block:#x} aliases inode {nid:#x}:{old:#x} and {:#x}:{slot:#x}", file.nid)
                    }
                }
            }
            FileData::Clustered(data) => for (slot, &block) in data.blocks.iter().enumerate() {
                if matches!(block, 0 | NEW_ADDR | COMPRESS_ADDR) { continue }
                if let Some((nid, old)) = used.insert(block, (file.nid, slot)) {
                    bail!("F2FS data block {block:#x} aliases inode {nid:#x}:{old:#x} and {:#x}:{slot:#x}", file.nid)
                }
            },
        }
    }
    Ok(())
}

pub fn resign(source: Blob, keys: &Keys, description: &str) -> Result<(Blob, usize)> {
    let (geometry, before) = candidates(&source)?;
    check_blocks(&before)?;
    let mut changes = Vec::new(); let mut changed = Vec::new();
    let mut count = 0;
    for item in before {
        let file = item.file;
        let mut data = item.data.clone();
        if !codesigner::sign_firmware(&mut data, &item.ranges, keys, &format!("{description}:inode-{:#x}", file.nid))? { continue }
        if item.data.iter().zip(&data).enumerate().any(|(at, (old, new))| old != new && !item.ranges.iter().any(|range| {
            range.key_type <= 1 && ((range.end - 0x208..range.end - 0x200).contains(&at)
                || (range.end - 0x200..range.end - 0x200 + 136).contains(&at))
        })) {
            bail!("{description}: CodeSigner update escaped the existing footer for inode {:#x}", file.nid)
        }
        for range in item.ranges.iter().filter(|range| range.key_type <= 1) {
            log!("CodeSigned {description}:{} ({})", file.name, if range.key_type == 0 { "TEE" } else { "REE" });
            count += 1;
        }
        changes.extend(rewrite_file(&source, geometry, &file, &item.data, &data)?);
        changed.push((file, data));
    }
    if changed.is_empty() { return Ok((source, count)) }
    let output = blob::patch(source, changes)?;
    for (file, data) in &changed {
        if read_file(&output, geometry, file)? != *data { bail!("{description}: rewritten F2FS firmware does not match for inode {:#x}", file.nid) }
    }
    Ok((output, count))
}
