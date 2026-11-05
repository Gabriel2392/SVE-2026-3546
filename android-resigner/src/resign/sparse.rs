use std::{io, sync::Arc};

use anyhow::{bail, Context, Result};

use super::blob::{self, Blob};
use crate::io::ReadAt;
const MAGIC: u32 = 0xed26_ff3a;
const RAW: u16 = 0xcac1;
const FILL: u16 = 0xcac2;
const SKIP: u16 = 0xcac3;
const CRC: u16 = 0xcac4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind { Raw, Fill(u32) }

#[derive(Clone, Copy, Debug)]
struct Chunk { kind: Kind, start: u64, blocks: u32 }

struct Filled { word: [u8; 4], len: u64 }

impl ReadAt for Filled {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len { return Ok(0) }
        let count = out.len().min((self.len - offset) as usize);
        for (index, byte) in out[..count].iter_mut().enumerate() { *byte = self.word[(offset as usize + index) & 3] }
        Ok(count)
    }
}

fn le16(data: &[u8], at: usize) -> Result<u16> { Ok(u16::from_le_bytes(data.get(at..at + 2).context("truncated sparse u16")?.try_into().unwrap())) }
fn le32(data: &[u8], at: usize) -> Result<u32> { Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated sparse u32")?.try_into().unwrap())) }

pub fn decode(source: Blob) -> Result<Blob> {
    let mut header = [0; 28]; source.read_exact_at(0, &mut header)?;
    if le32(&header, 0)? != MAGIC || le16(&header, 4)? != 1 { bail!("unsupported Android sparse image") }
    let file_header = le16(&header, 8)? as u64; let chunk_header = le16(&header, 10)? as u64; let block = le32(&header, 12)? as u64;
    if file_header < 28 || chunk_header < 12 || block < 4 || !block.is_power_of_two() { bail!("invalid Android sparse geometry") }
    let total = le32(&header, 16)? as u64; let chunks = le32(&header, 20)?; let mut physical = file_header; let mut blocks = 0u64; let mut parts = Vec::new();
    for _ in 0..chunks {
        let mut encoded = vec![0; chunk_header as usize]; source.read_exact_at(physical, &mut encoded)?;
        let kind = le16(&encoded, 0)?; let count = le32(&encoded, 4)? as u64; let size = le32(&encoded, 8)? as u64;
        let data = physical.checked_add(chunk_header).context("sparse offset overflow")?; let bytes = count.checked_mul(block).context("sparse chunk overflow")?;
        match kind {
            RAW => {
                if size != chunk_header + bytes { bail!("invalid sparse RAW chunk") }
                parts.push(blob::region(source.clone(), data, bytes)?);
            }
            FILL => {
                if size != chunk_header + 4 { bail!("invalid sparse FILL chunk") }
                let mut word = [0; 4]; source.read_exact_at(data, &mut word)?; parts.push(Arc::new(Filled { word, len: bytes }) as Blob);
            }
            SKIP => {
                if size != chunk_header { bail!("invalid sparse DONT_CARE chunk") }
                parts.push(blob::zeroes(bytes));
            }
            CRC => {
                if count != 0 || size != chunk_header + 4 { bail!("invalid sparse CRC chunk") }
            }
            _ => bail!("unsupported Android sparse chunk {kind:#x}"),
        }
        if kind != CRC { blocks = blocks.checked_add(count).context("sparse block count overflow")? }
        physical = physical.checked_add(size).context("sparse offset overflow")?;
    }
    if blocks != total || physical > source.len()? { bail!("Android sparse image is truncated or has the wrong block count") }
    Ok(blob::Concat::blob(parts)?)
}

pub fn decode_if_sparse(source: Blob) -> Result<Blob> {
    let mut magic = [0; 4]; source.read_exact_at(0, &mut magic)?;
    if u32::from_le_bytes(magic) == MAGIC { decode(source) } else { Ok(source) }
}

fn classify(block: &[u8]) -> Kind {
    let word = u32::from_le_bytes(block[..4].try_into().unwrap());
    if block.chunks_exact(4).all(|piece| piece == word.to_le_bytes()) { Kind::Fill(word) } else { Kind::Raw }
}

fn chunk_header(kind: Kind, blocks: u32, block: u32) -> Result<Vec<u8>> {
    let (tag, total) = match kind {
        Kind::Raw => (RAW, 12u64 + blocks as u64 * block as u64),
        Kind::Fill(_) => (FILL, 16),
    };
    let total = u32::try_from(total).context("Android sparse chunk exceeds 4 GiB")?;
    let mut out = Vec::with_capacity(12); out.extend_from_slice(&tag.to_le_bytes()); out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&blocks.to_le_bytes()); out.extend_from_slice(&total.to_le_bytes()); Ok(out)
}

pub fn encode(source: Blob, block: u32) -> Result<Blob> {
    if block < 4 || !block.is_power_of_two() { bail!("invalid Android sparse block size") }
    let size = source.len()?;
    if size == 0 || size % block as u64 != 0 { bail!("raw image is not sparse-block aligned") }
    let total_blocks = size / block as u64;
    if total_blocks > u32::MAX as u64 { bail!("raw image has too many sparse blocks") }
    let max_raw = ((u32::MAX as u64 - 12) / block as u64) as u32;
    let max_fill = (u32::MAX as u64 / block as u64) as u32;
    let mut chunks = Vec::<Chunk>::new();
    let mut buffer = vec![0; 4 << 20];
    let batch_blocks = (buffer.len() / block as usize).max(1);
    let mut index = 0u64;
    while index < total_blocks {
        crate::cancel::check()?;
        let count = batch_blocks.min((total_blocks - index) as usize);
        let bytes = count * block as usize;
        source.read_exact_at(index * block as u64, &mut buffer[..bytes])?;
        for piece in buffer[..bytes].chunks_exact(block as usize) {
            let kind = classify(piece);
            let limit = if kind == Kind::Raw { max_raw } else { max_fill };
            if let Some(last) = chunks.last_mut().filter(|last| last.kind == kind && last.blocks < limit) {
                last.blocks += 1;
            } else { chunks.push(Chunk { kind, start: index * block as u64, blocks: 1 }) }
            index += 1;
        }
    }
    let mut header = Vec::with_capacity(28); header.extend_from_slice(&MAGIC.to_le_bytes()); header.extend_from_slice(&1u16.to_le_bytes()); header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&28u16.to_le_bytes()); header.extend_from_slice(&12u16.to_le_bytes()); header.extend_from_slice(&block.to_le_bytes());
    header.extend_from_slice(&(total_blocks as u32).to_le_bytes()); header.extend_from_slice(&(chunks.len() as u32).to_le_bytes()); header.extend_from_slice(&0u32.to_le_bytes());
    let mut parts = Vec::with_capacity(1 + chunks.len() * 2); parts.push(blob::bytes(header));
    for chunk in chunks {
        parts.push(blob::bytes(chunk_header(chunk.kind, chunk.blocks, block)?));
        match chunk.kind {
            Kind::Raw => parts.push(blob::region(source.clone(), chunk.start, chunk.blocks as u64 * block as u64)?),
            Kind::Fill(word) => parts.push(blob::bytes(word.to_le_bytes().to_vec())),
        }
    }
    Ok(blob::Concat::blob(parts)?)
}
