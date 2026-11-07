use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::File,
    hash::Hasher,
    io,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use twox_hash::XxHash32;

use crate::{archive::{IndexedTarEntry, TarIndex}, io::{ReadAt, Region}};
use super::{archive::{Meta, TarMd5}, blob::Blob, incremental, sparse};

const MAGIC: u32 = 0x184d_2204;
const CACHE_BYTES: usize = 8 << 20;
const MAX_BLOCKS: usize = 1 << 20;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Copy, Debug)]
struct Block {
    encoded: u64,
    encoded_len: usize,
    decoded: u64,
    decoded_len: usize,
    raw: bool,
}

struct Cache {
    entries: VecDeque<(usize, Arc<Vec<u8>>)>,
    bytes: usize,
}

impl Cache {
    fn get(&mut self, index: usize) -> Option<Arc<Vec<u8>>> {
        let at = self.entries.iter().position(|(stored, _)| *stored == index)?;
        let value = self.entries.remove(at).unwrap();
        let data = value.1.clone(); self.entries.push_front(value); Some(data)
    }

    fn insert(&mut self, index: usize, data: Arc<Vec<u8>>) {
        while !self.entries.is_empty() && self.bytes.saturating_add(data.len()) > CACHE_BYTES {
            self.bytes -= self.entries.pop_back().unwrap().1.len();
        }
        self.bytes += data.len(); self.entries.push_front((index, data));
    }
}

pub(super) struct FrameBlob {
    source: Arc<dyn ReadAt>,
    blocks: Vec<Block>,
    len: u64,
    max_block: usize,
    cache: Mutex<Cache>,
}

fn read_exact(source: &dyn ReadAt, at: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0; len]; source.read_exact_at(at, &mut data)?; Ok(data)
}

fn decode_block(source: &dyn ReadAt, block: Block, max_block: usize) -> io::Result<Vec<u8>> {
    let encoded = read_exact(source, block.encoded, block.encoded_len)?;
    if block.raw {
        if encoded.len() != block.decoded_len { return Err(invalid("raw LZ4 block changed size")) }
        return Ok(encoded)
    }
    let mut decoded = vec![0; max_block];
    let len = lz4_flex::block::decompress_into(&encoded, &mut decoded)
        .map_err(|error| invalid(format!("invalid LZ4 block: {error}")))?;
    if len != block.decoded_len { return Err(invalid("LZ4 block decoded length changed")) }
    decoded.truncate(len); Ok(decoded)
}

impl FrameBlob {
    pub(super) fn open(region: Region) -> Result<Blob> {
        let source: Arc<dyn ReadAt> = Arc::new(region);
        let source_len = source.len()?;
        if source_len < 15 { bail!("LZ4 frame is too short") }
        let fixed = read_exact(source.as_ref(), 0, 6)?;
        if u32::from_le_bytes(fixed[..4].try_into().unwrap()) != MAGIC { bail!("not an LZ4 frame") }
        let flg = fixed[4]; let bd = fixed[5];
        if flg & 0xc0 != 0x40 || flg & 0x02 != 0 { bail!("unsupported LZ4 frame version or flags") }
        if flg & 0x20 == 0 { bail!("linked LZ4 blocks are unsupported for random access") }
        if flg & 0x08 == 0 { bail!("LZ4 frame has no content size") }
        if flg & 0x04 == 0 { bail!("LZ4 frame has no content checksum") }
        if flg & 0x01 != 0 { bail!("dictionary-backed LZ4 frame is unsupported") }
        if bd & !0x70 != 0 { bail!("invalid LZ4 block descriptor") }
        let max_block = match (bd >> 4) & 7 {
            4 => 64 << 10, 5 => 256 << 10, 6 => 1 << 20, 7 => 4 << 20,
            value => bail!("unsupported LZ4 maximum block size {value}"),
        };
        let header_len = 4 + 2 + 8 + 1;
        let header = read_exact(source.as_ref(), 0, header_len)?;
        let expected_header = (XxHash32::oneshot(0, &header[4..header_len - 1]) >> 8) as u8;
        if header[header_len - 1] != expected_header { bail!("invalid LZ4 frame header checksum") }
        let content_size = u64::from_le_bytes(header[6..14].try_into().unwrap());

        let block_checksum = flg & 0x10 != 0;
        let mut blocks = Vec::new(); let mut physical = header_len as u64; let mut logical = 0u64;
        let mut content_hash = XxHash32::with_seed(0);
        loop {
            if blocks.len() >= MAX_BLOCKS { bail!("LZ4 frame contains too many blocks") }
            let raw_size = u32::from_le_bytes(read_exact(source.as_ref(), physical, 4)?.try_into().unwrap()); physical += 4;
            if raw_size == 0 { break }
            let raw = raw_size & 0x8000_0000 != 0;
            let encoded_len = (raw_size & 0x7fff_ffff) as usize;
            if encoded_len == 0 || raw && encoded_len > max_block || !raw && encoded_len > max_block + max_block / 255 + 16 {
                bail!("invalid LZ4 block length {encoded_len}")
            }
            if physical.checked_add(encoded_len as u64).filter(|&end| end <= source_len).is_none() { bail!("truncated LZ4 block") }
            let encoded = read_exact(source.as_ref(), physical, encoded_len)?;
            if block_checksum {
                let expected = u32::from_le_bytes(read_exact(source.as_ref(), physical + encoded_len as u64, 4)?.try_into().unwrap());
                if XxHash32::oneshot(0, &encoded) != expected { bail!("invalid LZ4 block checksum") }
            }
            let decoded = if raw { encoded.clone() } else {
                let mut output = vec![0; max_block];
                let len = lz4_flex::block::decompress_into(&encoded, &mut output)
                    .map_err(|error| anyhow::anyhow!("invalid LZ4 block: {error}"))?;
                output.truncate(len); output
            };
            if decoded.is_empty() || decoded.len() > max_block { bail!("invalid decoded LZ4 block length") }
            content_hash.write(&decoded);
            blocks.push(Block { encoded: physical, encoded_len, decoded: logical, decoded_len: decoded.len(), raw });
            logical = logical.checked_add(decoded.len() as u64).context("LZ4 content size overflow")?;
            physical = physical.checked_add(encoded_len as u64 + if block_checksum { 4 } else { 0 }).context("LZ4 offset overflow")?;
        }
        if logical != content_size { bail!("LZ4 content size mismatch: {logical} != {content_size}") }
        let expected = u32::from_le_bytes(read_exact(source.as_ref(), physical, 4)?.try_into().unwrap()); physical += 4;
        if content_hash.finish() as u32 != expected { bail!("invalid LZ4 content checksum") }
        if physical != source_len { bail!("trailing data after LZ4 frame") }
        Ok(Arc::new(Self {
            source, blocks, len: logical, max_block,
            cache: Mutex::new(Cache { entries: VecDeque::new(), bytes: 0 }),
        }))
    }

    fn block(&self, index: usize) -> io::Result<Arc<Vec<u8>>> {
        if let Some(data) = self.cache.lock().unwrap_or_else(|error| error.into_inner()).get(index) { return Ok(data) }
        let data = Arc::new(decode_block(self.source.as_ref(), self.blocks[index], self.max_block)?);
        self.cache.lock().unwrap_or_else(|error| error.into_inner()).insert(index, data.clone()); Ok(data)
    }
}

impl ReadAt for FrameBlob {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || output.is_empty() { return Ok(0) }
        let mut at = offset; let mut written = 0;
        while written < output.len() && at < self.len {
            let index = self.blocks.partition_point(|block| block.decoded <= at).saturating_sub(1);
            let block = self.blocks[index];
            if at >= block.decoded + block.decoded_len as u64 { return Err(invalid("gap in LZ4 block index")) }
            let data = self.block(index)?; let within = (at - block.decoded) as usize;
            let count = (data.len() - within).min(output.len() - written);
            output[written..written + count].copy_from_slice(&data[within..within + count]);
            written += count; at += count as u64;
        }
        Ok(written)
    }
}

pub(super) struct StockInput {
    images: BTreeMap<String, Blob>,
    transport: BTreeMap<String, Blob>,
    metadata: BTreeMap<String, Meta>,
}

pub(super) trait ImageSource {
    fn image(&self, name: &str) -> Result<Blob>;
}

fn archive_kind(path: &Path) -> Result<String> {
    let name = path.file_name().and_then(|name| name.to_str()).with_context(|| format!("archive name is not UTF-8: {}", path.display()))?;
    if name.to_ascii_uppercase().starts_with("HOME_CSC_") { bail!("HOME_CSC cannot be used as the CSC archive") }
    let kind = name.split_once('_').map(|(kind, _)| kind.to_ascii_uppercase()).context("unrecognized Samsung archive name")?;
    if !matches!(kind.as_str(), "AP" | "CP" | "CSC") { bail!("expected AP, CP, or CSC archive, got {name}") }
    Ok(kind)
}

impl StockInput {
    pub(super) fn open(ap: &Path, cp: &Path, csc: &Path, names: impl IntoIterator<Item = String>) -> Result<Self> {
        let paths = [ap, cp, csc]; let mut kinds = BTreeSet::new(); let mut archives = Vec::new();
        for path in paths {
            let kind = archive_kind(path)?; if !kinds.insert(kind.clone()) { bail!("duplicate {kind} archive") }
            incremental::parse_trailer(path).with_context(|| format!("validating Odin trailer for {}", path.display()))?;
            let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
            archives.push(TarIndex::open(source).with_context(|| format!("reading {}", path.display()))?);
        }
        if kinds != BTreeSet::from(["AP".into(), "CP".into(), "CSC".into()]) { bail!("one AP, CP, and CSC archive are required") }
        Self::load(archives, names)
    }

    pub(super) fn single(path: &Path, names: impl IntoIterator<Item = String>) -> Result<Self> {
        incremental::parse_trailer(path).with_context(|| format!("validating Odin trailer for {}", path.display()))?;
        let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let index = TarIndex::open(source).with_context(|| format!("reading {}", path.display()))?;
        Self::load(vec![index], names)
    }

    fn load(archives: Vec<TarIndex>, names: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut images = BTreeMap::new(); let mut transport = BTreeMap::new(); let mut metadata = BTreeMap::new();
        for name in names {
            if name.is_empty() || name.contains(['/', '\\']) { bail!("unsafe configured image name {name:?}") }
            let packed = format!("{name}.lz4"); let mut found: Option<(&TarIndex, &IndexedTarEntry, bool)> = None;
            for index in &archives {
                for entry in index.entries().iter().filter(|entry| matches!(entry.kind, 0 | b'0')) {
                    let member = entry.name.rsplit('/').next();
                    let lz4 = member == Some(packed.as_str());
                    if !lz4 && member != Some(name.as_str()) { continue }
                    if found.is_some() { bail!("configured image {name} is ambiguous across firmware archives") }
                    found = Some((index, entry, lz4));
                }
            }
            let (index, entry, lz4) = found.with_context(|| format!("firmware archives are missing {name}"))?;
            let source: Blob = if lz4 { FrameBlob::open(index.region(entry)?)? } else { Arc::new(index.region(entry)?) };
            let raw = sparse::decode_if_sparse(source.clone()).with_context(|| format!("decoding {name}"))?;
            let meta = index.metadata(entry)?;
            metadata.insert(name.clone(), Meta { mode: meta.mode & 0o7777, mtime: meta.mtime });
            transport.insert(name.clone(), source); images.insert(name, raw);
        }
        Ok(Self { images, transport, metadata })
    }

    pub(super) fn image(&self, name: &str) -> Result<Blob> {
        self.images.get(name).cloned().with_context(|| format!("streaming input is missing {name}"))
    }

    pub(super) fn replace(&mut self, name: &str, source: Blob) -> Result<()> {
        if !self.images.contains_key(name) { bail!("replacement target is not a stock input: {name}") }
        let raw = sparse::decode_if_sparse(source.clone()).with_context(|| format!("decoding replacement {name}"))?;
        self.transport.insert(name.to_owned(), source); self.images.insert(name.to_owned(), raw); Ok(())
    }

    pub(super) fn transport(&self, name: &str) -> Result<Blob> {
        self.transport.get(name).cloned().with_context(|| format!("streaming transport is missing {name}"))
    }

    pub(super) fn names(&self) -> impl Iterator<Item = &str> { self.images.keys().map(String::as_str) }

    pub(super) fn pack(&self, output: &mut TarMd5, images: &mut BTreeMap<String, Blob>,
                       names: &[String], extra: Option<(String, Blob)>) -> Result<()> {
        for name in names {
            let image = images.remove(name).with_context(|| format!("rebuilt image is missing: {name}"))?;
            let meta = *self.metadata.get(name).with_context(|| format!("stock metadata is missing: {name}"))?;
            output.lz4(name, image, meta)?;
        }
        if !images.is_empty() { bail!("unexpected rebuilt images: {:?}", images.keys().collect::<Vec<_>>()) }
        if let Some((name, data)) = extra {
            output.member(&name, data, Meta { mode: 0o644, mtime: 0 }, b'0')?;
        }
        Ok(())
    }
}

impl ImageSource for StockInput {
    fn image(&self, name: &str) -> Result<Blob> { self.image(name) }
}
