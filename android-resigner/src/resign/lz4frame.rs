use std::{hash::Hasher, io::Write, os::raw::{c_char, c_int}, sync::{mpsc, Arc, Mutex}, thread};

use anyhow::Result;
use twox_hash::XxHash32;

use super::blob::Blob;
use crate::{io::ReadAt, par};

const MAGIC: u32 = 0x184d_2204;
const STORED: u32 = 0x8000_0000;

fn compress(data: &[u8]) -> Option<Vec<u8>> {
    let capacity = data.len().checked_sub(1)?;
    let mut output = vec![0u8; capacity];
    let size = unsafe {
        lz4::liblz4::LZ4_compress_default(data.as_ptr().cast::<c_char>(), output.as_mut_ptr().cast::<c_char>(),
            c_int::try_from(data.len()).ok()?, c_int::try_from(capacity).ok()?)
    };
    let size = usize::try_from(size).ok().filter(|&size| size != 0 && size < data.len())?;
    output.truncate(size);
    Some(output)
}

fn geometry(size: u64) -> (u64, u8) {
    if size <= 1 << 16 { (1 << 16, 4) } else if size <= 1 << 18 { (1 << 18, 5) } else { (1 << 20, 6) }
}

fn payload(data: &[u8]) -> u64 { compress(data).map_or(data.len(), |compressed| compressed.len()) as u64 }

static KNOWN: Mutex<Vec<(Blob, u64)>> = Mutex::new(Vec::new());

pub(super) fn digest_sized(source: &dyn ReadAt, skip: u64, mut consume: impl FnMut(&[u8])) -> Result<Vec<u64>> {
    let size = source.len()?;
    let block = geometry(size).0; let span = ((1 << 20) / block).max(1) * block;
    let mut sizes = Vec::new(); let mut at = 0u64;
    par::ordered(size.div_ceil(span) as usize, |index| -> Result<(Vec<u8>, Vec<u64>)> {
        let start = index as u64 * span;
        let mut data = vec![0; span.min(size - start) as usize];
        source.read_exact_at(start, &mut data)?;
        let sizes = data.chunks(block as usize).map(payload).collect();
        Ok((data, sizes))
    }, |(data, chunk)| {
        consume(&data[(skip.saturating_sub(at) as usize).min(data.len())..]);
        at += data.len() as u64; sizes.extend(chunk); Ok(())
    })?;
    Ok(sizes)
}

pub(super) fn remember(blob: &Blob, mut sizes: Vec<u64>) -> Result<()> {
    let size = blob.len()?;
    if let Some(first) = sizes.first_mut() {
        let mut data = vec![0; geometry(size).0.min(size) as usize]; blob.read_exact_at(0, &mut data)?; *first = payload(&data);
    }
    let total = if size > 0 { 15 } else { 7 } + sizes.iter().map(|size| size + 4).sum::<u64>() + 8;
    KNOWN.lock().unwrap_or_else(|error| error.into_inner()).push((blob.clone(), total));
    Ok(())
}

pub(super) fn known(blob: &Blob) -> Option<u64> {
    let mut known = KNOWN.lock().unwrap_or_else(|error| error.into_inner());
    let at = known.iter().position(|(item, _)| Arc::as_ptr(item) as *const () == Arc::as_ptr(blob) as *const ())?;
    Some(known.swap_remove(at).1)
}

pub(super) fn encode<W: Write>(source: Blob, mut writer: W) -> Result<W> {
    let size = source.len()?;
    let (block, id) = geometry(size);
    let mut header = MAGIC.to_le_bytes().to_vec();
    header.push(0x40 | 0x20 | if size > 0 { 0x08 } else { 0 } | 0x04);
    header.push(id << 4);
    if size > 0 { header.extend_from_slice(&size.to_le_bytes()); }
    header.push((XxHash32::oneshot(0, &header[4..]) >> 8) as u8);
    writer.write_all(&header)?;
    let (blocks, pending) = mpsc::sync_channel::<Vec<u8>>(par::threads() * 2);
    let hasher = thread::spawn(move || { let mut checksum = XxHash32::with_seed(0); for data in pending { checksum.write(&data) } checksum.finish() as u32 });
    let result = par::ordered(usize::try_from(size.div_ceil(block))?, |index| -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        crate::cancel::check()?;
        let at = index as u64 * block;
        let mut data = vec![0; block.min(size - at) as usize];
        source.read_exact_at(at, &mut data)?;
        let compressed = compress(&data);
        Ok((data, compressed))
    }, |(data, compressed)| {
        match compressed {
            Some(compressed) => {
                writer.write_all(&(compressed.len() as u32).to_le_bytes())?;
                writer.write_all(&compressed)?;
            }
            None => {
                writer.write_all(&(data.len() as u32 | STORED).to_le_bytes())?;
                writer.write_all(&data)?;
            }
        }
        let _ = blocks.send(data);
        Ok(())
    });
    drop(blocks);
    let checksum = hasher.join().map_err(|_| anyhow::anyhow!("LZ4 checksum worker panicked"))?;
    result?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&checksum.to_le_bytes())?;
    Ok(writer)
}
