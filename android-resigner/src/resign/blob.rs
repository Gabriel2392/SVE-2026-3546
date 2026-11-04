use std::{fs::File, io, path::Path, sync::Arc};

use crate::io::{Bytes, ReadAt, Region};

pub type Blob = Arc<dyn ReadAt>;

pub fn file(path: &Path) -> io::Result<Blob> { Ok(Arc::new(File::open(path)?)) }
pub fn bytes(data: Vec<u8>) -> Blob { Arc::new(Bytes(data)) }
pub fn region(source: Blob, start: u64, len: u64) -> io::Result<Blob> { Ok(Arc::new(Region::new(source, start, len)?)) }

pub struct Concat {
    pieces: Vec<(u64, Blob)>,
    len: u64,
}

impl Concat {
    pub fn new(parts: impl IntoIterator<Item = Blob>) -> io::Result<Self> {
        let mut pieces = Vec::new();
        let mut len = 0u64;
        for part in parts {
            pieces.push((len, part.clone()));
            len = len.checked_add(part.len()?).ok_or(io::ErrorKind::InvalidInput)?;
        }
        Ok(Self { pieces, len })
    }

    pub fn blob(parts: impl IntoIterator<Item = Blob>) -> io::Result<Blob> { Ok(Arc::new(Self::new(parts)?)) }
}

impl ReadAt for Concat {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || out.is_empty() { return Ok(0) }
        let mut written = 0;
        let mut at = offset;
        while written < out.len() && at < self.len {
            let index = self.pieces.partition_point(|(start, _)| *start <= at).saturating_sub(1);
            let (start, part) = &self.pieces[index];
            let n = part.read_at(at - *start, &mut out[written..])?;
            if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()) }
            written += n;
            at += n as u64;
        }
        Ok(written)
    }
}

pub struct Prefix {
    source: Blob,
    len: u64,
}

impl Prefix {
    pub fn blob(source: Blob, len: u64) -> io::Result<Blob> {
        if len > source.len()? { return Err(io::ErrorKind::UnexpectedEof.into()) }
        Ok(Arc::new(Self { source, len }))
    }
}

impl ReadAt for Prefix {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len { return Ok(0) }
        let n = out.len().min((self.len - offset) as usize);
        self.source.read_at(offset, &mut out[..n])
    }
}

pub struct Zeroes(pub u64);
impl ReadAt for Zeroes {
    fn len(&self) -> io::Result<u64> { Ok(self.0) }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.0 { return Ok(0) }
        let n = out.len().min((self.0 - offset) as usize);
        out[..n].fill(0);
        Ok(n)
    }
}

pub fn zeroes(len: u64) -> Blob { Arc::new(Zeroes(len)) }

pub fn patch(source: Blob, mut changes: Vec<(u64, Vec<u8>)>) -> io::Result<Blob> {
    overlay(source, changes.drain(..).map(|(at, data)| (at, bytes(data))).collect())
}

pub fn overlay(source: Blob, mut changes: Vec<(u64, Blob)>) -> io::Result<Blob> {
    changes.sort_by_key(|change| change.0);
    let len = source.len()?;
    let mut parts = Vec::with_capacity(changes.len() * 2 + 1);
    let mut at = 0;
    for (offset, data) in changes {
        let size = data.len()?;
        if offset < at || offset.checked_add(size).is_none_or(|end| end > len) { return Err(io::ErrorKind::InvalidInput.into()) }
        if offset > at { parts.push(region(source.clone(), at, offset - at)?) }
        at = offset + size;
        parts.push(data);
    }
    if at < len { parts.push(region(source, at, len - at)?) }
    Concat::blob(parts)
}

pub fn hash_range<D: sha2_10::Digest + Default>(source: &dyn ReadAt, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    let source_len = source.len()?;
    if offset.checked_add(len).is_none_or(|end| end > source_len) { return Err(io::ErrorKind::UnexpectedEof.into()) }
    let mut digest = D::new();
    let mut buffer = vec![0; 1 << 20];
    let mut at = 0;
    while at < len {
        let count = buffer.len().min((len - at) as usize);
        source.read_exact_at(offset + at, &mut buffer[..count])?;
        digest.update(&buffer[..count]);
        at += count as u64;
    }
    Ok(digest.finalize().to_vec())
}

pub fn hash<D: sha2_10::Digest + Default>(source: &dyn ReadAt, len: u64) -> io::Result<Vec<u8>> { hash_range::<D>(source, 0, len) }

pub fn read_all(source: &dyn ReadAt, limit: u64) -> io::Result<Vec<u8>> {
    let len = source.len()?;
    if len > limit || len > usize::MAX as u64 { return Err(io::Error::new(io::ErrorKind::OutOfMemory, format!("image is {len} bytes; in-memory limit is {limit}"))) }
    let mut data = vec![0; len as usize];
    source.read_exact_at(0, &mut data)?;
    Ok(data)
}
