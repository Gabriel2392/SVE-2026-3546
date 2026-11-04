use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use lz4::block::{self, CompressionMode};

use super::{blob::{self, Blob}, codesigner};

const MAGIC: u32 = 0xe0f5_e1e2;
const SB: u64 = 1024;
const SB_CSUM: u32 = 1;
const SHARED_PCLUSTER: u32 = 0x20;
const MAX_FILE: u64 = 512 << 20;
const PLAIN: u8 = 0;
const FULL: u8 = 1;
const INLINE: u8 = 2;
const COMPACT: u8 = 3;
const NONHEAD: u8 = 2;
const D0_BLOCKS: u16 = 1 << 11;

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
struct Inode { at: u64, layout: u8, mode: u16, size: u64, data: u32, header: u64, xattrs: u64 }

#[derive(Clone)]
struct Fs { source: Blob, block: u64, block_bits: u8, dir_block: usize, meta: u64, root: u64, zero_padding: bool, checksum: bool, shared: bool }

#[derive(Clone, Copy)]
struct Map { end: u64, advise: u16, algorithms: u8, bits: u8 }

#[derive(Clone, Copy)]
struct Cluster { lcn: usize, kind: u8, cluster_ofs: usize, delta0: u16, delta1: u16, block: u32, compressed_blocks: u16 }

#[derive(Clone, Copy)]
struct Extent { logical: usize, logical_len: usize, physical: u64, physical_len: usize, algorithm: u8, encoded: bool }

#[derive(Clone)]
struct Dirent { raw: [u8; 12], name: Vec<u8> }

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
        let checksum = u32le(&sb, 8)? & SB_CSUM != 0;
        if checksum { let (saved, actual) = sb_crc(&source, block)?; if saved != actual { bail!("invalid EROFS superblock checksum: {saved:08x} != {actual:08x}") } }
        let incompatible = u32le(&sb, 80)?;
        Ok(Self { source, block, block_bits, dir_block: dir_block as usize, meta, root: u16le(&sb, 14)? as u64,
            zero_padding: incompatible & 1 != 0, checksum, shared: incompatible & SHARED_PCLUSTER != 0 })
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
        if !matches!(layout, PLAIN | FULL | INLINE | COMPACT) { bail!("unsupported EROFS inode layout {layout}") }
        Ok(Inode { at, layout, mode: u16le(&data, 4)?, size, data: u32le(&data, 16)?, header, xattrs })
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
        let advise = u16le(&data, 4)?;
        if data[7] & 0x80 != 0 || advise & 0x28 != 0 || inode.layout == FULL && advise & 1 != 0 { bail!("unsupported EROFS compression format") }
        let bits = self.block_bits.checked_add(data[7] & 15).context("EROFS logical cluster size overflow")?;
        if bits > 24 { bail!("EROFS logical cluster is too large") }
        Ok(Map { end: at + 8, advise, algorithms: data[6], bits })
    }

    fn full_cluster(&self, map: Map, total: usize, lcn: usize) -> Result<Cluster> {
        if lcn >= total { bail!("EROFS logical cluster is out of range") }
        let at = map.end.checked_add(8 + lcn as u64 * 8).context("EROFS cluster index overflow")?;
        let mut data = [0; 8]; self.source.read_exact_at(at, &mut data)?;
        let advise = u16le(&data, 0)?; let kind = (advise & 3) as u8;
        let mut out = Cluster { lcn, kind, cluster_ofs: u16le(&data, 2)? as usize, delta0: 0, delta1: 0, block: 0, compressed_blocks: 0 };
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
        let mut out = Cluster { lcn: original, kind, cluster_ofs: low, delta0: 0, delta1: 0, block: 0, compressed_blocks: 0 };
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
                if big && low as u16 & D0_BLOCKS != 0 { cursor -= 1; blocks += low as u32 & !(D0_BLOCKS as u32); continue }
                cursor -= if big { low.checked_sub(2).context("invalid EROFS compact delta")? } else { low } as isize;
            }
            if !big && cursor >= 0 { blocks += 1 }
        }
        out.block = u32le(&pack, pack_size - 4)?.checked_add(blocks).context("EROFS physical block overflow")?;
        Ok(out)
    }

    fn cluster(&self, inode: Inode, map: Map, total: usize, lcn: usize, lookahead: bool) -> Result<Cluster> {
        if inode.layout == FULL { self.full_cluster(map, total, lcn) } else { self.compact_cluster(map, total, lcn, lookahead) }
    }

    fn extent(&self, inode: Inode, map: Map, offset: usize) -> Result<Extent> {
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
        if logical_len == 0 { bail!("zero-length EROFS compressed extent") }
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
            algorithm: if head.kind == 3 { map.algorithms >> 4 } else { map.algorithms & 15 }, encoded: head.kind != 0,
        })
    }

    fn decode(&self, extent: Extent) -> Result<Vec<u8>> {
        let mut physical = vec![0; extent.physical_len]; self.source.read_exact_at(extent.physical, &mut physical)?;
        if !extent.encoded {
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
        } else {
            let map = self.map(inode)?; let mut at = start as usize;
            while at < end as usize {
                let extent = self.extent(inode, map, at)?; let decoded = self.decode(extent)?;
                let extent_start = extent.logical as u64; let extent_end = extent_start + extent.logical_len as u64;
                let from = start.max(extent_start); let to = end.min(extent_end);
                if from < to {
                    let source = (from - extent_start) as usize..(to - extent_start) as usize;
                    let target = (from - start) as usize..(to - start) as usize;
                    out[target].copy_from_slice(&decoded[source]);
                }
                at = extent.logical + extent.logical_len;
            }
        }
        Ok(out)
    }

    fn read_inode(&self, inode: Inode) -> Result<Vec<u8>> {
        if inode.size > MAX_FILE { bail!("EROFS file exceeds the {MAX_FILE}-byte memory limit") }
        self.read_inode_range(inode, 0, inode.size as usize)
    }

    fn signed_files(&self, nid: u64, prefix: &str, seen: &mut BTreeSet<u64>, out: &mut Vec<String>) -> Result<()> {
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
                        self.signed_files(child, &path, seen, out)?;
                    }
                }
            }
            0o100000 if inode.size >= 0x210 && inode.size <= MAX_FILE => {
                let tail = self.read_inode_range(inode, inode.size - 0x210, 0x210)?;
                if codesigner::firmware_key_type(&tail).is_some() { out.push(prefix.to_owned()); }
            }
            _ => {}
        }
        Ok(())
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

    fn rewrite(&self, inode: Inode, old: &[u8], new: &[u8]) -> Result<Blob> {
        if old.len() != new.len() || old.len() as u64 != inode.size { bail!("EROFS COW replacement size changed: {} != {}", new.len(), inode.size) }
        if old == new { return Ok(self.source.clone()) }
        if self.shared { bail!("EROFS COW refuses a filesystem with shared pclusters or fragments") }
        let mut patches = Vec::new();
        if matches!(inode.layout, PLAIN | INLINE) {
            for (physical, logical, len) in self.flat_ranges(inode)? { diff(physical, &old[logical..logical + len], &new[logical..logical + len], &mut patches) }
        } else {
            let map = self.map(inode)?; let mut at = 0;
            while at < new.len() {
                let extent = self.extent(inode, map, at)?; let range = extent.logical..extent.logical + extent.logical_len;
                if old[range.clone()] != new[range.clone()] {
                    if extent.encoded {
                        if extent.algorithm != 0 { bail!("cannot rewrite EROFS compression algorithm {}", extent.algorithm) }
                        let encoded = block::compress(&new[range.clone()], Some(CompressionMode::HIGHCOMPRESSION(12)), false)?;
                        if encoded.len() > extent.physical_len { bail!("updated EROFS extent grew beyond its {}-byte pcluster: {} bytes", extent.physical_len, encoded.len()) }
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
        let mut output = blob::patch(self.source.clone(), patches)?;
        if self.checksum { let (saved, crc) = sb_crc(&output, self.block)?; if saved != crc { output = blob::patch(output, vec![(SB + 4, crc.to_le_bytes().to_vec())])? } }
        Ok(output)
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
        let output = self.rewrite(parent, &old, &new)?;
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

pub fn signed_firmware_paths(source: Blob) -> Result<Vec<String>> {
    let fs = Fs::open(source)?; let mut out = Vec::new(); let mut seen = BTreeSet::new();
    fs.signed_files(fs.root, "", &mut seen, &mut out)?; out.sort(); Ok(out)
}

pub fn replace(source: Blob, path: &str, data: &[u8]) -> Result<Blob> {
    let fs = Fs::open(source)?; let inode = fs.find(path)?;
    if inode.mode & 0o170000 != 0o100000 { bail!("EROFS target is not a regular file") }
    let old = fs.read_inode(inode)?; fs.rewrite(inode, &old, data)
}

pub fn remove(source: Blob, path: &str) -> Result<Blob> { Fs::open(source)?.unlink(path) }
