use std::{fs::File, io::{self, Seek, SeekFrom}, sync::Arc};

use crate::cancel;

pub trait ReadAt: Send + Sync {
    fn len(&self) -> io::Result<u64>;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            cancel::check()?;
            match self.read_at(offset, buf)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => {
                    offset = offset.checked_add(n as u64).ok_or(io::ErrorKind::InvalidInput)?;
                    buf = &mut buf[n..];
                }
            }
        }
        Ok(())
    }
}

impl ReadAt for File {
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    #[cfg(unix)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        std::os::windows::fs::FileExt::seek_read(self, buf, offset)
    }
}

pub fn write_all_at(file: &File, mut offset: u64, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        cancel::check()?;
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::write_at(file, buf, offset)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_write(file, buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        offset = offset.checked_add(n as u64).ok_or(io::ErrorKind::InvalidInput)?;
        buf = &buf[n..];
    }
    Ok(())
}

pub struct Window {
    source: Arc<dyn ReadAt>,
    start: u64,
    len: u64,
    pos: u64,
}

#[derive(Clone)]
pub struct Region {
    source: Arc<dyn ReadAt>,
    start: u64,
    len: u64,
}

impl Region {
    pub fn new(source: Arc<dyn ReadAt>, start: u64, len: u64) -> io::Result<Self> {
        let source_len = source.len()?;
        if start.checked_add(len).filter(|&end| end <= source_len).is_none() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Self { source, start, len })
    }

    pub fn reader(&self) -> Window {
        Window { source: self.source.clone(), start: self.start, len: self.len, pos: 0 }
    }
}

impl ReadAt for Region {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len { return Ok(0) }
        let n = buf.len().min(usize::try_from(self.len - offset).unwrap_or(usize::MAX));
        self.source.read_at(self.start + offset, &mut buf[..n])
    }
}

impl Window {
    pub fn new(source: Arc<dyn ReadAt>, start: u64, len: u64) -> io::Result<Self> {
        let source_len = source.len()?;
        if start.checked_add(len).filter(|&end| end <= source_len).is_none() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Self { source, start, len, pos: 0 })
    }
}

impl io::Read for Window {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(usize::try_from(self.len - self.pos).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(0);
        }
        self.source.read_exact_at(self.start + self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Window {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let pos = match from {
            SeekFrom::Start(pos) => pos as i128,
            SeekFrom::Current(delta) => self.pos as i128 + delta as i128,
            SeekFrom::End(delta) => self.len as i128 + delta as i128,
        };
        if !(0..=self.len as i128).contains(&pos) { return Err(io::ErrorKind::InvalidInput.into()) }
        self.pos = pos as u64;
        Ok(self.pos)
    }
}

pub struct Bytes(pub Vec<u8>);

impl ReadAt for Bytes {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(src) = usize::try_from(offset).ok().and_then(|at| self.0.get(at..)) else { return Ok(0) };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}
