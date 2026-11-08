use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use lz4::block::{self, CompressionMode};

use super::{blob::{self, Blob}, codesigner, crypto::Keys};
use crate::par;

const MAGIC: u32 = 0xe0f5_e1e2;
const SB: u64 = 1024;
const SB_CSUM: u32 = 1;
const FRAGMENTS: u32 = 0x20;
const ZTAILPACKING: u32 = 0x10;
const BIT48: u32 = 0x80;
const MAX_FILE: u64 = 512 << 20;
const PLAIN: u8 = 0;
const FULL: u8 = 1;
const INLINE: u8 = 2;
const COMPACT: u8 = 3;
const CHUNK: u8 = 4;
const NONHEAD: u8 = 2;
const D0_BLOCKS: u16 = 1 << 11;
const CHUNK_BITS: u16 = 0x1f;
const CHUNK_INDEXES: u16 = 0x20;
const CHUNK_48BIT: u16 = 0x40;
const SIGN_TRIES: u32 = 4096;

fn u16le(data: &[u8], at: usize) -> Result<u16> { Ok(u16::from_le_bytes(data.get(at..at + 2).context("truncated EROFS u16")?.try_into().unwrap())) }
fn u32le(data: &[u8], at: usize) -> Result<u32> { Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated EROFS u32")?.try_into().unwrap())) }
fn u64le(data: &[u8], at: usize) -> Result<u64> { Ok(u64::from_le_bytes(data.get(at..at + 8).context("truncated EROFS u64")?.try_into().unwrap())) }
fn align8(value: u64) -> Result<u64> { value.checked_add(7).map(|value| value & !7).context("EROFS offset overflow") }

fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data { crc ^= byte as u32; for _ in 0..8 { crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1)) } }
    crc
}

fn sb_crc(source: &Blob, block: u64) -> Result<(u32, u32)> {
    let mut data = vec![0; if block > SB { block - SB } else { block } as usize]; source.read_exact_at(SB, &mut data)?;
    let saved = u32le(&data, 4)?; data[4..8].fill(0); Ok((saved, crc32c(!0, &data)))
}

#[derive(Clone, Copy)]
struct Inode { nid: u64, at: u64, layout: u8, mode: u16, size: u64, data: u64, header: u64, xattrs: u64 }

#[derive(Clone)]
struct Fs { source: Blob, block: u64, blocks: u64, block_bits: u8, dir_block: usize, meta: u64, root: u64, packed: u64, zero_padding: bool, checksum: bool, fragments: bool, ztail: bool, bit48: bool }

#[derive(Clone, Copy)]
struct Map { end: u64, advise: u16, algorithms: u8, bits: u8, extents: u64, fragment: Option<u64>, inline: Option<usize>, whole_fragment: bool }

#[derive(Clone, Copy)]
struct Cluster { lcn: usize, kind: u8, cluster_ofs: usize, delta0: u16, delta1: u16, block: u32, compressed_blocks: u16, pack_end: u64 }

#[derive(Clone, Copy)]
struct Extent { logical: usize, logical_len: usize, physical: u64, physical_len: usize, block: u32, algorithm: u8, encoded: bool, interlaced: bool, pack_end: u64, fragment: Option<u64> }

#[derive(Clone, Copy)]
enum Tail { Fragment(u64), Inline(u64, usize) }

#[derive(Clone, Copy)]
struct Physical { start: u64, end: u64, nid: u64 }

#[derive(Clone, Copy)]
struct Chunk { physical: Option<u64>, logical: usize, len: usize }

#[derive(Clone)]
struct Dirent { raw: [u8; 12], name: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FirmwareFile { pub path: String, pub ranges: Vec<codesigner::FirmwareRange>, pub data: Vec<u8> }

fn valid_path(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.split('/').any(|part| matches!(part, "" | "." | "..")) { bail!("invalid EROFS path {path:?}") }
    Ok(())
}

fn dirents(block: &[u8]) -> Result<Vec<Dirent>> {
    if block.len() < 12 { bail!("truncated EROFS directory block") }
    let first = u16le(block, 8)? as usize;
    if first == 0 || first % 12 != 0 || first > block.len() { bail!("invalid EROFS directory block") }
    let count = first / 12; let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * 12; let start = u16le(block, at + 8)? as usize;
        let mut end = if index + 1 == count { block.len() } else { u16le(block, at + 20)? as usize };
        if start < first || start > end || end > block.len() { bail!("invalid EROFS directory name") }
        while end > start && block[end - 1] == 0 { end -= 1 }
        let name = block.get(start..end).context("truncated EROFS directory name")?;
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') { bail!("invalid EROFS directory name") }
        out.push(Dirent { raw: block[at..at + 12].try_into().unwrap(), name: name.to_vec() });
    }
    Ok(out)
}

fn encode_dirents(entries: &[Dirent], size: usize) -> Result<Vec<u8>> {
    if entries.is_empty() { bail!("cannot encode an empty EROFS directory block") }
    let mut at = entries.len().checked_mul(12).context("EROFS directory overflow")?;
    if at.checked_add(entries.iter().map(|entry| entry.name.len()).sum::<usize>()).is_none_or(|end| end > size) { bail!("EROFS directory entries no longer fit their block") }
    let mut out = vec![0; size];
    for (index, entry) in entries.iter().enumerate() {
        let header = index * 12; out[header..header + 12].copy_from_slice(&entry.raw);
        out[header + 8..header + 10].copy_from_slice(&u16::try_from(at).context("EROFS directory name offset overflow")?.to_le_bytes());
        out[at..at + entry.name.len()].copy_from_slice(&entry.name); at += entry.name.len();
    }
    Ok(out)
}

impl Fs {
    fn open(source: Blob) -> Result<Self> {
        let mut sb = [0; 128]; source.read_exact_at(SB, &mut sb)?;
        if u32le(&sb, 0)? != MAGIC { bail!("invalid EROFS magic") }
        let block_bits = sb[12];
        if !(9..=24).contains(&block_bits) { bail!("invalid EROFS block size") }
        let block = 1u64 << block_bits;
        let dir_bits = sb[90];
        let dir_block = if dir_bits == 0 { block } else { 1u64.checked_shl(dir_bits.into()).context("invalid EROFS directory block size")? };
        if dir_block < 512 || dir_block > 1 << 20 { bail!("unsupported EROFS directory block size {dir_block}") }
        let meta = (u32le(&sb, 40)? as u64).checked_mul(block).context("EROFS metadata offset overflow")?;
        let incompatible = u32le(&sb, 80)?;
        let root8 = if incompatible & BIT48 != 0 { u64le(&sb, 112)? } else { 0 };
        let blocks = u32le(&sb, 36)? as u64 | if root8 != 0 { (u16le(&sb, 14)? as u64) << 32 } else { 0 };
        let source_len = source.len()?;
        if blocks.checked_mul(block).is_none_or(|end| end > source_len) { bail!("EROFS blocks exceed image") }
        let checksum = u32le(&sb, 8)? & SB_CSUM != 0;
        if checksum { let (saved, actual) = sb_crc(&source, block)?; if saved != actual { bail!("invalid EROFS superblock checksum: {saved:08x} != {actual:08x}") } }
        let root = if root8 != 0 { root8 } else { u16le(&sb, 14)? as u64 };
        Ok(Self { source, block, blocks, block_bits, dir_block: dir_block as usize, meta, root,
            packed: u64le(&sb, 96)?,
            zero_padding: incompatible & 1 != 0, checksum, fragments: incompatible & FRAGMENTS != 0,
            ztail: incompatible & ZTAILPACKING != 0, bit48: root8 != 0 })
    }

    fn inode(&self, nid: u64) -> Result<Inode> {
        let at = self.meta.checked_add(nid.checked_mul(32).context("EROFS inode offset overflow")?).context("EROFS inode offset overflow")?;
        let mut data = [0; 64]; self.source.read_exact_at(at, &mut data)?;
        let format = u16le(&data, 0)?;
        let header = if format & 1 == 0 { 32 } else { 64 };
        let size = if header == 32 { u32le(&data, 8)? as u64 } else { u64le(&data, 8)? };
        let xattr_count = u16le(&data, 2)? as u64;
        let xattrs = if xattr_count == 0 { 0 } else { 12 + (xattr_count - 1) * 4 };
        let layout = ((format >> 1) & 7) as u8;
        if !matches!(layout, PLAIN | FULL | INLINE | COMPACT | CHUNK) { bail!("unsupported EROFS inode layout {layout}") }
        let high = if self.bit48 && (header == 64 || format & 0x10 != 0) { u16le(&data, 6)? as u64 } else { 0 };
        Ok(Inode { nid, at, layout, mode: u16le(&data, 4)?, size, data: u32le(&data, 16)? as u64 | high << 32, header, xattrs })
    }

    fn chunks(&self, inode: Inode) -> Result<Vec<Chunk>> {
        if inode.layout != CHUNK { bail!("EROFS inode does not use chunks") }
        let format = inode.data as u16;
        if format & !(CHUNK_BITS | CHUNK_INDEXES | CHUNK_48BIT) != 0 { bail!("unsupported EROFS chunk format {format:#x}") }
        let bits = self.block_bits.checked_add((format & CHUNK_BITS) as u8).context("EROFS chunk size overflow")?;
        if bits > 31 { bail!("EROFS chunk size is too large") }
        let size = 1usize << bits;
        let unit = if format & CHUNK_INDEXES != 0 { 8 } else { 4 };
        if format & CHUNK_48BIT != 0 && unit != 8 { bail!("invalid EROFS 48 bit chunk format") }
        let mut index = inode.at.checked_add(inode.header + inode.xattrs).context("EROFS chunk index overflow")?;
        index = index.checked_add((unit - index as usize % unit) as u64 % unit as u64).context("EROFS chunk index overflow")?;
        let count = usize::try_from(inode.size).context("EROFS file is too large")?.div_ceil(size);
        let source_len = self.source.len()?;
        let mut out = Vec::with_capacity(count);
        for chunk in 0..count {
            let mut raw = [0; 8]; self.source.read_exact_at(index + (chunk * unit) as u64, &mut raw[..unit])?;
            let block = if unit == 4 { u32::from_le_bytes(raw[..4].try_into().unwrap()) as u64 } else {
                let high = u16::from_le_bytes(raw[..2].try_into().unwrap()) as u64;
                let device = u16::from_le_bytes(raw[2..4].try_into().unwrap());
                if device != 0 { bail!("EROFS chunk uses external device {device}") }
                let low = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as u64;
                let mask = if format & CHUNK_48BIT != 0 { (1u64 << 48) - 1 } else { u32::MAX as u64 };
                ((high << 32) | low) & mask
            };
            let null = if format & CHUNK_48BIT != 0 { (1u64 << 48) - 1 } else { u32::MAX as u64 };
            let logical = chunk * size; let len = (inode.size as usize - logical).min(size);
            let physical = (block != null).then(|| block << self.block_bits);
            if physical.is_some_and(|at| at.checked_add(len as u64).is_none_or(|end| end > source_len)) {
                bail!("EROFS chunk exceeds image")
            }
            out.push(Chunk { physical, logical, len });
        }
        Ok(out)
    }

    fn flat_ranges(&self, inode: Inode) -> Result<Vec<(u64, usize, usize)>> {
        let size = usize::try_from(inode.size).context("EROFS file is too large")?;
        match inode.layout {
            PLAIN => Ok(vec![((inode.data as u64).checked_mul(self.block).context("EROFS data offset overflow")?, 0, size)]),
            INLINE => {
                let full = size / self.block as usize * self.block as usize;
                let mut out = Vec::with_capacity(2);
                if full != 0 { out.push(((inode.data as u64).checked_mul(self.block).context("EROFS data offset overflow")?, 0, full)) }
                if full != size { out.push((inode.at.checked_add(inode.header + inode.xattrs).context("EROFS inline offset overflow")?, full, size - full)) }
                Ok(out)
            }
            _ => bail!("EROFS inode is compressed"),
        }
    }

    fn map(&self, inode: Inode) -> Result<Map> {
        let at = align8(inode.at.checked_add(inode.header + inode.xattrs).context("EROFS map offset overflow")?)?;
        let mut data = [0; 8]; self.source.read_exact_at(at, &mut data)?;
        if data[7] & 0x80 != 0 {
            if !self.fragments { bail!("EROFS fragment inode has no fragment feature") }
            return Ok(Map { end: at + 8, advise: 0x20, algorithms: 0, bits: self.block_bits,
                extents: 0, fragment: Some(u64::from_le_bytes(data) ^ (1u64 << 63)), inline: None, whole_fragment: true })
        }
        let advise = u16le(&data, 4)?;
        let bits = self.block_bits.checked_add(data[7] & 15).context("EROFS logical cluster size overflow")?;
        if bits > 24 { bail!("EROFS logical cluster is too large") }
        let table = inode.layout == FULL && advise & 1 != 0;
        let extents = if !table { 0 } else if 4usize << ((advise >> 1) & 3) < 16 { inode.size.div_ceil(1 << bits) } else {
            u32le(&data, 0)? as u64 | (u16le(&data, 6)? as u64) << 32
        };
        let fragment = if advise & 0x20 != 0 { Some(if table { 0 } else { u32le(&data, 0)? as u64 }) } else { None };
        let inline = if advise & 0x08 != 0 { Some(u16le(&data, 2)? as usize) } else { None };
        if fragment.is_some() && !self.fragments { bail!("EROFS fragment has no fragment feature") }
        if inline.is_some() && !self.ztail { bail!("EROFS inline pcluster has no tail packing feature") }
        Ok(Map { end: at + 8, advise, algorithms: data[6], bits, extents, fragment, inline, whole_fragment: false })
    }

    fn full_cluster(&self, map: Map, total: usize, lcn: usize) -> Result<Cluster> {
        if lcn >= total { bail!("EROFS logical cluster is out of range") }
        let at = map.end.checked_add(8 + lcn as u64 * 8).context("EROFS cluster index overflow")?;
        let mut data = [0; 8]; self.source.read_exact_at(at, &mut data)?;
        let advise = u16le(&data, 0)?; let kind = (advise & 3) as u8;
        let mut out = Cluster { lcn, kind, cluster_ofs: u16le(&data, 2)? as usize, delta0: 0, delta1: 0, block: 0, compressed_blocks: 0, pack_end: at + 8 };
        let a = u16le(&data, 4)?; let b = u16le(&data, 6)?;
        if kind == NONHEAD {
            out.cluster_ofs = 1usize << map.bits; out.delta0 = a; out.delta1 = b;
            if out.delta0 & D0_BLOCKS != 0 { out.compressed_blocks = out.delta0 & !D0_BLOCKS; out.delta0 = 1 }
        } else { out.block = u32::from(a) | u32::from(b) << 16 }
        Ok(out)
    }

    fn compact_cluster(&self, map: Map, total: usize, original: usize, lookahead: bool) -> Result<Cluster> {
        if original >= total || map.bits > 14 { bail!("EROFS compact cluster is out of range") }
        let initial = ((32 - map.end as usize % 32) / 4) & 7;
        let compact2 = if map.advise & 1 != 0 && initial < total { (total - initial) & !15 } else { 0 };
        let mut at = map.end; let mut lcn = original; let mut shift = 2;
        if lcn >= initial {
            at += (initial * 4) as u64; lcn -= initial;
            if lcn < compact2 { shift = 1 } else { at += (compact2 * 2) as u64; lcn -= compact2 }
        }
        at = at.checked_add((lcn << shift) as u64).context("EROFS compact index overflow")?;
        let count = if shift == 2 && map.bits <= 14 { 2 } else if shift == 1 && map.bits <= 12 { 16 } else { bail!("unsupported EROFS compact index format") };
        let pack_size = count << shift; let base = at as usize & !(pack_size - 1); let index = (at as usize & (pack_size - 1)) >> shift;
        let mut pack = vec![0; pack_size]; self.source.read_exact_at(base as u64, &mut pack)?;
        let low_bits = usize::from(map.bits.max(12)); let encoded_bits = (pack_size - 4) * 8 / count;
        let (mut low, kind) = compact_bits(low_bits, &pack, encoded_bits * index)?;
        let mut out = Cluster { lcn: original, kind, cluster_ofs: low, delta0: 0, delta1: 0, block: 0, compressed_blocks: 0, pack_end: (base + pack_size) as u64 };
        if kind == NONHEAD {
            out.cluster_ofs = 1usize << map.bits;
            if lookahead { out.delta1 = compact_distance(low_bits, encoded_bits, count, &pack, index)? as u16 }
            if low as u16 & D0_BLOCKS != 0 { out.compressed_blocks = low as u16 & !D0_BLOCKS; out.delta0 = 1 }
            else if index + 1 != count { out.delta0 = low as u16 }
            else {
                let (previous, previous_kind) = compact_bits(low_bits, &pack, encoded_bits * (index - 1))?;
                low = if previous_kind != NONHEAD { 0 } else if previous as u16 & D0_BLOCKS != 0 { 1 } else { previous };
                out.delta0 = (low + 1) as u16;
            }
            return Ok(out)
        }
        let big = map.advise & 2 != 0; let mut blocks = if big { 0 } else { 1 }; let mut cursor = index as isize;
        while cursor > 0 {
            cursor -= 1; let (low, kind) = compact_bits(low_bits, &pack, encoded_bits * cursor as usize)?;
            if kind == NONHEAD {
                if !big { cursor -= low as isize }
                else if low as u16 & D0_BLOCKS != 0 { cursor -= 1; blocks += low as u32 & !(D0_BLOCKS as u32); continue }
                else { cursor -= low.checked_sub(2).context("invalid EROFS compact delta")? as isize; continue }
            }
            if cursor >= 0 { blocks += 1 }
        }
        out.block = u32le(&pack, pack_size - 4)?.checked_add(blocks).context("EROFS physical block overflow")?;
        Ok(out)
    }

    fn cluster(&self, inode: Inode, map: Map, total: usize, lcn: usize, lookahead: bool) -> Result<Cluster> {
        if inode.layout == FULL { self.full_cluster(map, total, lcn) } else { self.compact_cluster(map, total, lcn, lookahead) }
    }

    fn extent_record(&self, inode: Inode, map: Map, offset: usize) -> Result<Extent> {
        let recsize = 4usize << ((map.advise >> 1) & 3);
        if map.extents == 0 { bail!("EROFS extent table is empty") }
        let count = usize::try_from(map.extents).context("EROFS extent count is too large")?;
        let base = map.end.checked_add((recsize - map.end as usize % recsize) as u64 % recsize as u64).context("EROFS extent index overflow")?;
        let (index, logical, end, value, physical) = if recsize < 16 {
            let cluster = 1usize << map.bits; let index = offset / cluster;
            if index >= count { bail!("EROFS extent lookup exceeds its table") }
            let logical = index.checked_mul(cluster).context("EROFS extent offset overflow")? as u64;
            let end = inode.size.min(logical.checked_add(cluster as u64).context("EROFS extent offset overflow")?);
            if recsize == 4 {
                let mut raw = vec![0; 8 + (index + 1) * 4]; self.source.read_exact_at(base, &mut raw)?;
                let mut physical = u64::from_le_bytes(raw[..8].try_into().unwrap());
                for record in raw[8..8 + index * 4].chunks_exact(4) {
                    physical = physical.checked_add((u32::from_le_bytes(record.try_into().unwrap()) & 0x001f_ffff) as u64).context("EROFS physical offset overflow")?;
                }
                (index, logical, end, u32le(&raw, 8 + index * 4)?, physical)
            } else {
                let at = base.checked_add((index * 8) as u64).context("EROFS extent index overflow")?;
                let mut raw = [0; 8]; self.source.read_exact_at(at, &mut raw)?;
                (index, logical, end, u32le(&raw, 0)?, u32le(&raw, 4)? as u64)
            }
        } else {
            let record = |index: usize| -> Result<(Vec<u8>, u64)> {
                let at = base.checked_add((index * recsize) as u64).context("EROFS extent index overflow")?;
                let mut raw = vec![0; recsize]; self.source.read_exact_at(at, &mut raw)?;
                let logical = u32le(&raw, 12)? as u64 | if recsize >= 20 { (u32le(&raw, 16)? as u64) << 32 } else { 0 };
                Ok((raw, logical))
            };
            let (mut low, mut high) = (0, count);
            while high - low > 1 { let mid = (low + high) / 2; if record(mid)?.1 > offset as u64 { high = mid } else { low = mid } }
            let (raw, logical) = record(low)?;
            if logical > offset as u64 { bail!("EROFS extent lookup failed") }
            let end = if low + 1 == count { inode.size } else { record(low + 1)?.1 };
            (low, logical, end, u32le(&raw, 0)?, u32le(&raw, 4)? as u64 | (u32le(&raw, 8)? as u64) << 32)
        };
        if logical >= end || end > inode.size || offset as u64 >= end { bail!("invalid EROFS extent bounds") }
        if index + 1 == count && map.fragment.is_some() {
            let high = if recsize > 4 { (u32::try_from(physical).context("EROFS fragment offset overflow")? as u64) << 32 } else { 0 };
            return Ok(Extent { logical: logical as usize, logical_len: (end - logical) as usize,
                physical: 0, physical_len: 0, block: 0, algorithm: 0, encoded: true,
                interlaced: false, pack_end: 0, fragment: Some(value as u64 | high) })
        }
        let format = value >> 28;
        let physical_len = (value & 0x001f_ffff) as usize;
        if physical_len == 0 {
            return Ok(Extent { logical: logical as usize, logical_len: (end - logical) as usize,
                physical: 0, physical_len: 0, block: 0, algorithm: 0, encoded: false,
                interlaced: false, pack_end: 0, fragment: None })
        }
        Ok(Extent { logical: logical as usize, logical_len: (end - logical) as usize,
            physical, physical_len, block: u32::try_from(physical >> 32).unwrap_or(u32::MAX),
            algorithm: format.saturating_sub(1) as u8, encoded: format != 0,
            interlaced: format == 0 && map.advise & 0x10 != 0 && physical as usize % self.block as usize == 0
                && physical_len % self.block as usize == 0, pack_end: 0, fragment: None })
    }

    fn extent(&self, inode: Inode, map: Map, offset: usize) -> Result<Extent> {
        if map.extents != 0 { return self.extent_record(inode, map, offset) }
        let cluster_size = 1usize << map.bits; let size = inode.size as usize; let total = size.div_ceil(cluster_size);
        let initial = self.cluster(inode, map, total, offset >> map.bits, false)?;
        let (head_lcn, head) = if initial.kind != NONHEAD && offset & (cluster_size - 1) >= initial.cluster_ofs { (initial.lcn, initial) } else {
            let mut distance = if initial.kind == NONHEAD { initial.delta0 as usize } else { 1 }; let mut lcn = initial.lcn;
            loop {
                if distance == 0 || lcn < distance { bail!("invalid EROFS compressed lookback") }
                lcn -= distance; let found = self.cluster(inode, map, total, lcn, false)?;
                if found.kind != NONHEAD { break (lcn, found) }
                distance = found.delta0 as usize;
            }
        };
        let logical = (head_lcn << map.bits) | head.cluster_ofs;
        let mut next = head_lcn + 1;
        let logical_len = loop {
            if next << map.bits >= size { break size.checked_sub(logical).context("invalid EROFS compressed extent")? }
            let found = self.cluster(inode, map, total, next, true)?;
            if found.kind != NONHEAD { break ((next << map.bits) | found.cluster_ofs).checked_sub(logical).context("invalid EROFS compressed extent")? }
            next = next.checked_add(found.delta1.max(1) as usize).context("EROFS extent overflow")?;
        };
        if logical_len == 0 { bail!("empty EROFS compressed extent") }
        let big1 = map.advise & 2 != 0; let big2 = map.advise & 4 != 0; let eof = (head_lcn + 1) << map.bits >= size;
        let mut physical_blocks = 1usize;
        if !eof && !((head.kind == 1 && !big1) || (matches!(head.kind, 0 | 3) && !big2)) {
            let found = self.cluster(inode, map, total, head_lcn + 1, false)?;
            if found.kind == NONHEAD && found.delta0 == 1 && found.compressed_blocks != 0 { physical_blocks = found.compressed_blocks as usize }
        }
        Ok(Extent {
            logical, logical_len,
            physical: (head.block as u64).checked_mul(self.block).context("EROFS physical offset overflow")?,
            physical_len: physical_blocks.checked_mul(self.block as usize).context("EROFS physical size overflow")?,
            block: head.block,
            algorithm: if head.kind == 3 { map.algorithms >> 4 } else { map.algorithms & 15 }, encoded: head.kind != 0,
            interlaced: head.kind == 0 && map.advise & 0x10 != 0,
            pack_end: head.pack_end, fragment: None,
        })
    }

    fn tail_extent(&self, inode: Inode, map: Map) -> Result<Option<(usize, Tail)>> {
        if map.fragment.is_none() && map.inline.is_none() { return Ok(None) }
        let mut at = 0; let mut last = None; let mut last_encoded = None;
        while at < inode.size as usize {
            let extent = self.extent(inode, map, at)?;
            if let Some(offset) = extent.fragment {
                if extent.logical + extent.logical_len != inode.size as usize { bail!("EROFS fragment is not last") }
                return Ok(Some((extent.logical, Tail::Fragment(offset))))
            }
            last = Some((extent.logical, extent.block, extent.pack_end));
            if extent.encoded { last_encoded = last; }
            let next = extent.logical.checked_add(extent.logical_len).context("EROFS extent overflow")?;
            if next <= at { bail!("EROFS extent made no progress") }
            at = next;
        }
        let (logical, high, mut pack_end) = if map.fragment.is_some() {
            last_encoded.context("EROFS fragment has no encoded extent")?
        } else { last.context("EROFS inline file has no extent")? };
        if map.inline.is_some() {
            let cluster_size = 1usize << map.bits;
            let total = (inode.size as usize).div_ceil(cluster_size);
            pack_end = self.cluster(inode, map, total, total - 1, false)?.pack_end;
        }
        let source = if let Some(low) = map.fragment {
            Tail::Fragment(low | if inode.layout == FULL { (high as u64) << 32 } else { 0 })
        } else { Tail::Inline(pack_end, map.inline.unwrap()) };
        Ok(Some((logical, source)))
    }

    fn read_packed(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        if self.packed == 0 { bail!("EROFS fragment has no packed inode") }
        let inode = self.inode(self.packed)?;
        if inode.nid == self.packed && inode.mode & 0o170000 != 0o100000 { bail!("EROFS packed inode is not regular") }
        out.copy_from_slice(&self.read_inode_range(inode, offset, out.len())?);
        Ok(())
    }

    fn decode(&self, extent: Extent) -> Result<Vec<u8>> {
        if extent.physical_len == 0 { return Ok(vec![0; extent.logical_len]) }
        let mut physical = vec![0; extent.physical_len]; self.source.read_exact_at(extent.physical, &mut physical)?;
        if !extent.encoded {
            if extent.interlaced {
                if extent.physical_len > self.block as usize || extent.logical_len > extent.physical_len { bail!("invalid EROFS interlaced extent") }
                let skip = extent.logical % self.block as usize; let mut out = Vec::with_capacity(extent.logical_len);
                let right = (self.block as usize - skip).min(extent.logical_len);
                out.extend_from_slice(&physical[skip..skip + right]); out.extend_from_slice(&physical[..extent.logical_len - right]);
                return Ok(out)
            }
            physical.truncate(extent.logical_len); return Ok(physical)
        }
        if extent.algorithm != 0 { bail!("unsupported EROFS compression algorithm {}", extent.algorithm) }
        let encoded = if self.zero_padding { &physical[physical.iter().position(|&byte| byte != 0).context("empty EROFS compressed extent")?..] } else { &physical };
        let expected = i32::try_from(extent.logical_len).context("EROFS extent exceeds LZ4 limit")?;
        let decoded = block::decompress(encoded, Some(expected)).with_context(|| format!("invalid EROFS LZ4 extent at {:#x} ({} physical bytes, {} logical bytes)", extent.physical, encoded.len(), extent.logical_len))?;
        if decoded.len() != extent.logical_len { bail!("EROFS extent decoded to {} bytes, expected {}", decoded.len(), extent.logical_len) }
        Ok(decoded)
    }

    fn read_inode_range(&self, inode: Inode, start: u64, len: usize) -> Result<Vec<u8>> {
        let end = start.checked_add(len as u64).filter(|&end| end <= inode.size).context("EROFS read range exceeds file")?;
        let mut out = vec![0; len];
        if matches!(inode.layout, PLAIN | INLINE) {
            for (physical, logical, physical_len) in self.flat_ranges(inode)? {
                let logical = logical as u64;
                let physical_end = logical + physical_len as u64;
                let from = start.max(logical); let to = end.min(physical_end);
                if from < to {
                    let target = (from - start) as usize..(to - start) as usize;
                    self.source.read_exact_at(physical + from - logical, &mut out[target])?;
                }
            }
        } else if inode.layout == CHUNK {
            for chunk in self.chunks(inode)? {
                let logical = chunk.logical as u64; let physical_end = logical + chunk.len as u64;
                let from = start.max(logical); let to = end.min(physical_end);
                if from >= to { continue }
                let target = (from - start) as usize..(to - start) as usize;
                if let Some(physical) = chunk.physical {
                    self.source.read_exact_at(physical + from - logical, &mut out[target])?;
                }
            }
        } else {
            let map = self.map(inode)?;
            if map.whole_fragment {
                self.read_packed(map.fragment.context("EROFS fragment offset is missing")? + start, &mut out)?;
                return Ok(out)
            }
            let tail = self.tail_extent(inode, map)?; let mut at = start as usize;
            while at < end as usize {
                let extent = self.extent(inode, map, at)?;
                let extent_start = extent.logical as u64; let extent_end = extent_start + extent.logical_len as u64;
                let from = start.max(extent_start); let to = end.min(extent_end);
                if from < to {
                    let target = (from - start) as usize..(to - start) as usize;
                    if tail.is_some_and(|(logical, _)| logical == extent.logical) {
                        match tail.unwrap().1 {
                            Tail::Fragment(offset) => self.read_packed(offset + from - extent_start, &mut out[target])?,
                            Tail::Inline(offset, size) => {
                                let mut physical = vec![0; size]; self.source.read_exact_at(offset, &mut physical)?;
                                let source = (from - extent_start) as usize..(to - extent_start) as usize;
                                if extent.encoded {
                                    let encoded = if self.zero_padding { &physical[physical.iter().position(|&byte| byte != 0).context("empty EROFS inline pcluster")?..] } else { &physical };
                                    let decoded = block::decompress(encoded, Some(extent.logical_len as i32))?;
                                    out[target].copy_from_slice(&decoded[source]);
                                } else { out[target].copy_from_slice(&physical[source]); }
                            }
                        }
                    } else {
                        let decoded = self.decode(extent)?;
                        let source = (from - extent_start) as usize..(to - extent_start) as usize;
                        out[target].copy_from_slice(&decoded[source]);
                    }
                }
                at = extent.logical + extent.logical_len;
            }
        }
        Ok(out)
    }

    fn read_inode(&self, inode: Inode) -> Result<Vec<u8>> {
        if inode.size > MAX_FILE { bail!("EROFS file exceeds {MAX_FILE} bytes") }
        self.read_inode_range(inode, 0, inode.size as usize)
    }

    fn inode_refs(&self, nid: u64, seen: &mut BTreeSet<u64>, out: &mut Vec<Physical>) -> Result<()> {
        if !seen.insert(nid) { return Ok(()) }
        crate::cancel::check()?;
        let inode = self.inode(nid)?;
        let kind = inode.mode & 0o170000;
        if matches!(kind, 0o040000 | 0o100000 | 0o120000) {
            if matches!(inode.layout, PLAIN | INLINE) {
                for (start, _, len) in self.flat_ranges(inode)? {
                    out.push(Physical { start, end: start.checked_add(len as u64).context("EROFS physical range overflow")?, nid });
                }
            } else if inode.layout == CHUNK {
                for chunk in self.chunks(inode)? {
                    if let Some(start) = chunk.physical {
                        out.push(Physical { start, end: start.checked_add(chunk.len as u64).context("EROFS physical range overflow")?, nid });
                    }
                }
            } else {
                let map = self.map(inode)?;
                if !map.whole_fragment {
                    let tail = self.tail_extent(inode, map)?; let mut at = 0;
                    while at < inode.size as usize {
                        let extent = self.extent(inode, map, at)?;
                        if extent.physical_len != 0 && !tail.is_some_and(|(logical, _)| logical == extent.logical) {
                            out.push(Physical { start: extent.physical,
                                end: extent.physical.checked_add(extent.physical_len as u64).context("EROFS physical range overflow")?, nid });
                        }
                        at = extent.logical.checked_add(extent.logical_len).context("EROFS logical range overflow")?;
                    }
                }
            }
        }
        if kind == 0o040000 {
            for block in self.read_inode(inode)?.chunks(self.dir_block) {
                for entry in dirents(block)? {
                    if matches!(entry.name.as_slice(), b"." | b"..") { continue }
                    self.inode_refs(u64::from_le_bytes(entry.raw[..8].try_into().unwrap()), seen, out)?;
                }
            }
        }
        Ok(())
    }

    fn references(&self) -> Result<Vec<Physical>> {
        let mut out = Vec::new(); let mut seen = BTreeSet::new();
        self.inode_refs(self.root, &mut seen, &mut out)?;
        if self.packed != 0 { self.inode_refs(self.packed, &mut seen, &mut out)?; }
        Ok(out)
    }

    fn exclusive(inode: Inode, start: u64, len: usize, refs: &[Physical]) -> Result<bool> {
        let end = start.checked_add(len as u64).context("EROFS physical range overflow")?;
        let mut owners = refs.iter().filter(|item| item.start < end && start < item.end);
        Ok(owners.next().is_some_and(|item| item.nid == inode.nid) && owners.next().is_none())
    }

    fn regular_files(&self, nid: u64, prefix: &str, seen: &mut BTreeSet<u64>, out: &mut Vec<(String, Inode)>) -> Result<()> {
        if !seen.insert(nid) { return Ok(()) }
        let inode = self.inode(nid)?;
        match inode.mode & 0o170000 {
            0o040000 => {
                let directory = self.read_inode(inode)?;
                for block in directory.chunks(self.dir_block) {
                    for entry in dirents(block)? {
                        if matches!(entry.name.as_slice(), b"." | b"..") { continue }
                        let name = std::str::from_utf8(&entry.name).context("EROFS filename is not UTF-8")?;
                        if name.is_empty() || name.contains('/') || name.contains('\\') { bail!("unsafe EROFS filename {name:?}") }
                        let path = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") };
                        let child = u64::from_le_bytes(entry.raw[..8].try_into().unwrap());
                        self.regular_files(child, &path, seen, out)?;
                    }
                }
            }
            0o100000 if inode.size >= 0x210 && inode.size <= MAX_FILE => out.push((prefix.to_owned(), inode)),
            _ => {}
        }
        Ok(())
    }

    fn firmware(&self, path: &str, inode: Inode) -> Result<Option<FirmwareFile>> {
        crate::cancel::check()?;
        let head = self.read_inode_range(inode, 0, 4)?;
        let tail = self.read_inode_range(inode, inode.size - 0x210, 0x210)?;
        if head != b"\x7fELF" && codesigner::firmware_key_type(&tail).is_none() { return Ok(None) }
        let data = self.read_inode(inode)?;
        let ranges = codesigner::firmware_ranges(&data)?;
        let data = if ranges.iter().any(|range| range.key_type <= 1) { data } else { Vec::new() };
        Ok((!ranges.is_empty()).then(|| FirmwareFile { path: path.to_owned(), ranges, data }))
    }

    fn child(&self, inode: Inode, wanted: &str) -> Result<Option<u64>> {
        if inode.mode & 0o170000 != 0o040000 { bail!("EROFS path component before {wanted:?} is not a directory") }
        let directory = self.read_inode(inode)?; let mut found = None;
        for block in directory.chunks(self.dir_block) {
            for entry in dirents(block)? {
                if entry.name == wanted.as_bytes() {
                    let nid = u64::from_le_bytes(entry.raw[..8].try_into().unwrap());
                    if found.replace(nid).is_some() { bail!("duplicate EROFS directory entry {wanted:?}") }
                }
            }
        }
        Ok(found)
    }

    fn find_opt(&self, path: &str) -> Result<Option<Inode>> {
        valid_path(path)?;
        let mut inode = self.inode(self.root)?;
        for wanted in path.split('/') {
            let Some(nid) = self.child(inode, wanted)? else { return Ok(None) };
            inode = self.inode(nid)?;
        }
        Ok(Some(inode))
    }

    fn find(&self, path: &str) -> Result<Inode> { self.find_opt(path)?.with_context(|| format!("EROFS path not found: {path}")) }

    fn finish(&self, mut output: Blob) -> Result<Blob> {
        if self.checksum {
            let (saved, crc) = sb_crc(&output, self.block)?;
            if saved != crc { output = blob::patch(output, vec![(SB + 4, crc.to_le_bytes().to_vec())])?; }
        }
        Ok(output)
    }

    fn clone_plain(&self, inode: Inode, data: &[u8]) -> Result<Blob> {
        if data.len() as u64 > MAX_FILE { bail!("EROFS file exceeds {MAX_FILE} bytes") }
        let count = u64::try_from(data.len().div_ceil(self.block as usize)).context("EROFS block count overflow")?;
        let end = self.blocks.checked_add(count).context("EROFS block count overflow")?;
        let bytes = usize::try_from(count.checked_mul(self.block).context("EROFS clone size overflow")?).context("EROFS clone size overflow")?;
        let at = self.blocks.checked_mul(self.block).context("EROFS clone offset overflow")?;
        let limit = self.source.len()?;
        if at > limit { bail!("EROFS block count exceeds its payload") }
        let available = usize::try_from(limit - at).context("EROFS trailing size overflow")?;
        let existing = available.min(bytes);
        if existing != 0 {
            let mut data = vec![0; existing]; self.source.read_exact_at(at, &mut data)?;
            if data.iter().any(|&byte| byte != 0) { bail!("EROFS clone area is not empty") }
        }
        let mut raw = vec![0; bytes];
        raw[..data.len()].copy_from_slice(data);
        let mut raw_format = [0; 2]; self.source.read_exact_at(inode.at, &mut raw_format)?;
        let format = u16::from_le_bytes(raw_format) & !0x0e;
        let size = if inode.header == 32 {
            u32::try_from(data.len()).context("EROFS compact inode size overflow")?.to_le_bytes().to_vec()
        } else { (data.len() as u64).to_le_bytes().to_vec() };
        let mut patches = vec![
            (inode.at, format.to_le_bytes().to_vec()),
            (inode.at + 8, size),
            (inode.at + 16, (self.blocks as u32).to_le_bytes().to_vec()),
            (SB + 36, (end as u32).to_le_bytes().to_vec()),
        ];
        if self.bit48 {
            let high = u16::try_from(self.blocks >> 32).context("EROFS block address exceeds 48 bits")?;
            if inode.header == 64 || format & 0x10 != 0 { patches.push((inode.at + 6, high.to_le_bytes().to_vec())); }
            else if high != 0 { bail!("EROFS compact inode cannot store a 48 bit block address") }
            patches.push((SB + 14, u16::try_from(end >> 32).context("EROFS block count exceeds 48 bits")?.to_le_bytes().to_vec()));
        } else if end > u32::MAX as u64 { bail!("EROFS block count exceeds 32 bits") }
        if existing != 0 { patches.push((at, raw[..existing].to_vec())); }
        let output = blob::patch(self.source.clone(), patches)?;
        let output = if existing == raw.len() { output } else {
            blob::Concat::blob([output, blob::bytes(raw[existing..].to_vec())])?
        };
        self.finish(output)
    }

    fn rewrite(&self, inode: Inode, old: &[u8], new: &mut [u8], refs: &mut Option<Vec<Physical>>, keys: Option<&Keys>) -> Result<Blob> {
        if old.len() as u64 != inode.size { bail!("EROFS source size changed: {} != {}", old.len(), inode.size) }
        if old == new { return Ok(self.source.clone()) }
        let clone = |refs: &mut Option<Vec<Physical>>, data: &[u8]| { *refs = None; self.clone_plain(inode, data) };
        if old.len() != new.len() { return clone(refs, new) }
        if refs.is_none() { *refs = Some(self.references()?) }
        let mut patches = Vec::new();
        if matches!(inode.layout, PLAIN | INLINE) {
            for (physical, logical, len) in self.flat_ranges(inode)? {
                if old[logical..logical + len] != new[logical..logical + len] {
                    if !Self::exclusive(inode, physical, len, refs.as_ref().unwrap())? { return clone(refs, new) }
                    diff(physical, &old[logical..logical + len], &new[logical..logical + len], &mut patches)
                }
            }
        } else if inode.layout == CHUNK {
            for chunk in self.chunks(inode)? {
                let range = chunk.logical..chunk.logical + chunk.len;
                if old[range.clone()] == new[range.clone()] { continue }
                let Some(physical) = chunk.physical else {
                    if new[range].iter().any(|&byte| byte != 0) { return clone(refs, new) }
                    continue
                };
                if !Self::exclusive(inode, physical, chunk.len, refs.as_ref().unwrap())? { return clone(refs, new) }
                diff(physical, &old[range.clone()], &new[range], &mut patches);
            }
        } else {
            let map = self.map(inode)?; let mut at = 0;
            if map.whole_fragment || self.tail_extent(inode, map)?.is_some() { return clone(refs, new) }
            while at < new.len() {
                let extent = self.extent(inode, map, at)?; let range = extent.logical..extent.logical + extent.logical_len;
                if old[range.clone()] != new[range.clone()] {
                    if !Self::exclusive(inode, extent.physical, extent.physical_len, refs.as_ref().unwrap())? { return clone(refs, new) }
                    if extent.encoded {
                        if extent.algorithm != 0 { return clone(refs, new) }
                        let mut encoded = block::compress(&new[range.clone()], Some(CompressionMode::HIGHCOMPRESSION(12)), false)?;
                        if encoded.len() > extent.physical_len {
                            let Some(keys) = keys else { return clone(refs, new) };
                            let signed = codesigner::firmware_ranges(new)?.into_iter().filter(|&item| {
                                let signature = codesigner::firmware_signature(item);
                                range.start <= signature.start && signature.end <= range.end
                                    && old[signature.clone()] != new[signature]
                            }).collect::<Vec<_>>();
                            if signed.is_empty() { return clone(refs, new) }
                            let saved = signed.iter().map(|&item| {
                                let signature = codesigner::firmware_signature(item); (signature.clone(), new[signature].to_vec())
                            }).collect::<Vec<_>>();
                            for attempt in 0..SIGN_TRIES {
                                codesigner::vary_firmware(new, &signed, keys, attempt)?;
                                encoded = block::compress(&new[range.clone()], Some(CompressionMode::HIGHCOMPRESSION(12)), false)?;
                                if encoded.len() <= extent.physical_len { break }
                            }
                            if encoded.len() > extent.physical_len {
                                for (signature, value) in saved { new[signature].copy_from_slice(&value); }
                                return clone(refs, new)
                            }
                        }
                        let mut data = vec![0; extent.physical_len];
                        let at = if self.zero_padding { data.len() - encoded.len() } else { 0 }; data[at..at + encoded.len()].copy_from_slice(&encoded);
                        let decoded = block::decompress(&encoded, Some(extent.logical_len as i32))?;
                        if decoded != new[range] { bail!("internal EROFS recompression verification failed") }
                        patches.push((extent.physical, data));
                    } else { diff(extent.physical, &old[range.clone()], &new[range], &mut patches) }
                }
                at = extent.logical + extent.logical_len;
            }
        }
        self.finish(blob::patch(self.source.clone(), patches)?)
    }

    fn unlink(&self, path: &str) -> Result<Blob> {
        valid_path(path)?;
        let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = if parent_path.is_empty() { self.inode(self.root)? } else { self.find(parent_path)? };
        if parent.mode & 0o170000 != 0o040000 { bail!("EROFS parent of {path:?} is not a directory") }
        let old = self.read_inode(parent)?; let mut new = old.clone(); let mut target = None;
        for (index, block) in old.chunks(self.dir_block).enumerate() {
            let mut entries = dirents(block)?;
            if let Some(at) = entries.iter().position(|entry| entry.name == name.as_bytes()) {
                let nid = u64::from_le_bytes(entries[at].raw[..8].try_into().unwrap());
                if target.replace(nid).is_some() { bail!("duplicate EROFS path: {path}") }
                entries.remove(at);
                let encoded = encode_dirents(&entries, block.len())?; let start = index * self.dir_block;
                new[start..start + block.len()].copy_from_slice(&encoded);
            }
        }
        let inode = self.inode(target.with_context(|| format!("EROFS path not found: {path}"))?)?;
        if inode.mode & 0o170000 != 0o100000 { bail!("EROFS removal target is not a regular file: {path}") }
        let output = self.rewrite(parent, &old, &mut new, &mut None, None)?;
        if Fs::open(output.clone())?.find_opt(path)?.is_some() { bail!("EROFS removal verification failed: {path}") }
        Ok(output)
    }
}

fn compact_bits(low_bits: usize, input: &[u8], bit: usize) -> Result<(usize, u8)> {
    let byte = bit / 8; let shift = bit & 7; let data = input.get(byte..byte + 4).context("truncated EROFS compact index")?;
    let value = u32::from_le_bytes(data.try_into().unwrap()) >> shift; let mask = (1u32 << low_bits) - 1;
    Ok(((value & mask) as usize, ((value >> low_bits) & 3) as u8))
}

fn compact_distance(low_bits: usize, encoded_bits: usize, count: usize, input: &[u8], mut index: usize) -> Result<usize> {
    let mut distance = 0;
    loop {
        let (low, kind) = compact_bits(low_bits, input, encoded_bits * index)?;
        if kind != NONHEAD { return Ok(distance) }
        distance += 1; index += 1;
        if index == count { return Ok(distance + if low as u16 & D0_BLOCKS == 0 { low.saturating_sub(1) } else { 0 }) }
    }
}

fn diff(base: u64, old: &[u8], new: &[u8], out: &mut Vec<(u64, Vec<u8>)>) {
    let mut at = 0;
    while at < old.len() {
        while at < old.len() && old[at] == new[at] { at += 1 }
        let start = at;
        while at < old.len() && old[at] != new[at] { at += 1 }
        if start != at { out.push((base + start as u64, new[start..at].to_vec())) }
    }
}

pub fn read(source: Blob, path: &str) -> Result<Vec<u8>> { let fs = Fs::open(source)?; let inode = fs.find(path)?; fs.read_inode(inode) }

pub(super) fn signed_firmware(source: Blob) -> Result<Vec<FirmwareFile>> {
    let fs = Fs::open(source)?; let mut files = Vec::new();
    fs.regular_files(fs.root, "", &mut BTreeSet::new(), &mut files)?;
    let mut out = Vec::new();
    par::ordered(files.len(), |index| fs.firmware(&files[index].0, files[index].1), |file| { out.extend(file); Ok(()) })?;
    out.sort_by(|left, right| left.path.cmp(&right.path)); Ok(out)
}

pub fn replace(source: Blob, path: &str, data: &[u8]) -> Result<Blob> {
    replace_all(source, &[(path.to_owned(), data.to_vec())])
}

fn replace_files(mut source: Blob, files: &mut [(String, Vec<u8>)], keys: Option<&Keys>) -> Result<Blob> {
    let mut refs = None;
    for (path, data) in files {
        let fs = Fs::open(source)?; let inode = fs.find(path)?;
        if inode.mode & 0o170000 != 0o100000 { bail!("EROFS target is not a regular file") }
        let old = fs.read_inode(inode)?;
        source = fs.rewrite(inode, &old, data, &mut refs, keys).with_context(|| format!("rewriting {path}"))?;
    }
    Ok(source)
}

pub fn replace_all(source: Blob, files: &[(String, Vec<u8>)]) -> Result<Blob> {
    replace_files(source, &mut files.to_vec(), None)
}

pub fn replace_signed(source: Blob, files: &mut [(String, Vec<u8>)], keys: &Keys) -> Result<Blob> {
    replace_files(source, files, Some(keys))
}

pub fn remove(source: Blob, path: &str) -> Result<Blob> { Fs::open(source)?.unlink(path) }
