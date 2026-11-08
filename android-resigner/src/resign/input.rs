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

use crate::{archive::{IndexedTarEntry, TarIndex}, io::{ReadAt, Region}, par};
use super::{archive::{Meta, TarMd5}, blob::Blob, incremental, sparse};

const MAGIC: u32 = 0x184d_2204;
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

type Slot = Arc<Mutex<Option<Arc<Vec<u8>>>>>;

pub(super) struct FrameBlob {
    source: Arc<dyn ReadAt>,
    blocks: Vec<Block>,
    len: u64,
    cache: Mutex<VecDeque<(usize, Slot)>>,
    capacity: usize,
}

fn read_exact(source: &dyn ReadAt, at: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0; len]; source.read_exact_at(at, &mut data)?; Ok(data)
}

fn decompress(encoded: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    let mut decoded = vec![0; capacity];
    let len = lz4::block::decompress_to_buffer(encoded, Some(capacity as i32), &mut decoded)
        .map_err(|error| invalid(format!("invalid LZ4 block: {error}")))?;
    decoded.truncate(len); Ok(decoded)
}

fn decode_block(source: &dyn ReadAt, block: Block) -> io::Result<Vec<u8>> {
    let encoded = read_exact(source, block.encoded, block.encoded_len)?;
    if block.raw {
        if encoded.len() != block.decoded_len { return Err(invalid("raw LZ4 block changed size")) }
        return Ok(encoded)
    }
    let decoded = decompress(&encoded, block.decoded_len)?;
    if decoded.len() != block.decoded_len { return Err(invalid("LZ4 block decoded length changed")) }
    Ok(decoded)
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
        let mut blocks = Vec::new(); let mut physical = header_len as u64;
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
            blocks.push(Block { encoded: physical, encoded_len, decoded: 0, decoded_len: 0, raw });
            physical = physical.checked_add(encoded_len as u64 + if block_checksum { 4 } else { 0 }).context("LZ4 offset overflow")?;
        }
        let expected = u32::from_le_bytes(read_exact(source.as_ref(), physical, 4)?.try_into().unwrap()); physical += 4;
        if physical != source_len { bail!("trailing data after LZ4 frame") }
        let mut content_hash = XxHash32::with_seed(0); let mut lens = Vec::with_capacity(blocks.len());
        par::ordered(blocks.len(), |index| -> Result<Vec<u8>> {
            let block = blocks[index];
            let encoded = read_exact(source.as_ref(), block.encoded, block.encoded_len)?;
            if block_checksum {
                let expected = u32::from_le_bytes(read_exact(source.as_ref(), block.encoded + block.encoded_len as u64, 4)?.try_into().unwrap());
                if XxHash32::oneshot(0, &encoded) != expected { bail!("invalid LZ4 block checksum") }
            }
            let decoded = if block.raw { encoded } else { decompress(&encoded, max_block)? };
            if decoded.is_empty() || decoded.len() > max_block { bail!("invalid decoded LZ4 block length") }
            Ok(decoded)
        }, |decoded| { content_hash.write(&decoded); lens.push(decoded.len()); Ok(()) })?;
        let mut logical = 0u64;
        for (block, len) in blocks.iter_mut().zip(lens) {
            block.decoded = logical; block.decoded_len = len;
            logical = logical.checked_add(len as u64).context("LZ4 content size overflow")?;
        }
        if logical != content_size { bail!("LZ4 content size mismatch: {logical} != {content_size}") }
        if content_hash.finish() as u32 != expected { bail!("invalid LZ4 content checksum") }
        Ok(Arc::new(Self { source, blocks, len: logical, cache: Mutex::new(VecDeque::new()), capacity: ((par::threads() * (4 << 20)) / max_block).max(8) }))
    }

    fn block(&self, index: usize) -> io::Result<Arc<Vec<u8>>> {
        let slot = {
            let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
            match cache.iter().position(|(stored, _)| *stored == index) {
                Some(at) => { let entry = cache.remove(at).unwrap(); let slot = entry.1.clone(); cache.push_front(entry); slot }
                None => {
                    let slot = Slot::default(); cache.push_front((index, slot.clone()));
                    cache.truncate(self.capacity); slot
                }
            }
        };
        let mut value = slot.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(data) = value.as_ref() { return Ok(data.clone()) }
        let data = Arc::new(decode_block(self.source.as_ref(), self.blocks[index])?);
        *value = Some(data.clone()); Ok(data)
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

pub(super) trait ImageSource: Sync {
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
            incremental::check_later(path).with_context(|| format!("validating Odin trailer for {}", path.display()))?;
            let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
            archives.push(TarIndex::open(source).with_context(|| format!("reading {}", path.display()))?);
        }
        if kinds != BTreeSet::from(["AP".into(), "CP".into(), "CSC".into()]) { bail!("one AP, CP, and CSC archive are required") }
        Self::load(archives, names)
    }

    pub(super) fn single(path: &Path, names: impl IntoIterator<Item = String>) -> Result<Self> {
        incremental::check_later(path).with_context(|| format!("validating Odin trailer for {}", path.display()))?;
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
