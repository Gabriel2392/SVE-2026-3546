use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, path::Path, sync::{mpsc, Arc}, thread::{self, JoinHandle}};

use anyhow::{bail, Context, Result};
use md5::{Digest, Md5};

use super::{blob::Blob, lz4frame};
use crate::io::{ReadAt, Window, write_all_at};

const BLOCK: u64 = 512;
const RECORD: u64 = 20 * BLOCK;
const BUFFER: usize = 4 << 20;

#[derive(Clone, Copy)]
pub struct Meta { pub mode: u32, pub mtime: u64 }


fn number(field: &mut [u8], mut value: u64) -> Result<()> {
    if u128::from(value) < 8u128.pow((field.len() - 1) as u32) {
        field.copy_from_slice(format!("{:0width$o}\0", value, width = field.len() - 1).as_bytes());
        return Ok(())
    }
    field.fill(0);
    for byte in field[1..].iter_mut().rev() { *byte = value as u8; value >>= 8 }
    if value != 0 { bail!("GNU tar numeric field overflow") }
    field[0] = 0x80;
    Ok(())
}

fn header(name: &str, size: u64, meta: Meta, kind: u8) -> Result<[u8; 512]> {
    if name.is_empty() || name.len() > 255 || !name.is_ascii() { bail!("tar member name is unsupported: {name:?}") }
    let (prefix, name) = if name.len() <= 100 {
        ("", name)
    } else {
        name.match_indices('/').rev().find_map(|(at, _)| {
            let prefix = &name[..at]; let name = &name[at + 1..];
            (prefix.len() <= 155 && !name.is_empty() && name.len() <= 100).then_some((prefix, name))
        }).with_context(|| format!("tar member name is too long: {name}"))?
    };
    let mut out = [0u8; 512];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    number(&mut out[100..108], meta.mode as u64)?;
    number(&mut out[108..116], 0)?;
    number(&mut out[116..124], 0)?;
    number(&mut out[124..136], size)?;
    number(&mut out[136..148], meta.mtime)?;
    out[148..156].fill(b' ');
    out[156] = if kind == 0 { b'0' } else { kind };
    out[257..265].copy_from_slice(b"ustar  \0");
    out[265..269].copy_from_slice(b"root");
    out[297..301].copy_from_slice(b"root");
    let checksum: u64 = out.iter().map(|&byte| byte as u64).sum();
    let encoded = format!("{checksum:06o}\0 ");
    if encoded.len() != 8 { bail!("tar checksum overflow") }
    out[148..156].copy_from_slice(encoded.as_bytes());
    Ok(out)
}

struct At<'a> { file: &'a File, pos: u64, ready: Option<mpsc::Sender<u64>> }

impl Write for At<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        write_all_at(self.file, self.pos, data)?; self.pos += data.len() as u64;
        if let Some(ready) = &self.ready { let _ = ready.send(self.pos); }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

pub struct TarMd5 { file: Arc<File>, len: u64, tar_name: String, ready: Option<mpsc::Sender<u64>>, hasher: Option<JoinHandle<io::Result<Vec<u8>>>> }

impl TarMd5 {
    pub fn create(path: &Path, tar_name: &str) -> Result<Self> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        Ok(Self::new(file, tar_name))
    }

    pub(super) fn new(file: File, tar_name: &str) -> Self {
        let file = Arc::new(file);
        let reader = file.clone();
        let (ready, pending) = mpsc::channel::<u64>();
        let hasher = thread::spawn(move || {
            let mut hash = Md5::new(); let mut at = 0u64; let mut buffer = vec![0; BUFFER];
            for end in pending {
                while at < end {
                    let count = buffer.len().min((end - at) as usize);
                    reader.read_exact_at(at, &mut buffer[..count])?; hash.update(&buffer[..count]); at += count as u64;
                }
            }
            Ok(hash.finalize().to_vec())
        });
        Self { file, len: 0, tar_name: tar_name.to_owned(), ready: Some(ready), hasher: Some(hasher) }
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        write_all_at(&self.file, self.len, data)?; self.len += data.len() as u64; Ok(())
    }

    fn mark(&self) { if let Some(ready) = &self.ready { let _ = ready.send(self.len); } }

    fn pad(&mut self) -> Result<()> {
        let padding = ((BLOCK - self.len % BLOCK) % BLOCK) as usize;
        if padding != 0 { self.write(&[0; 512][..padding])? }
        Ok(())
    }

    pub(super) fn bytes(&mut self, data: &[u8]) -> Result<()> { self.write(data)?; self.mark(); Ok(()) }

    pub(super) fn plain(&mut self, header: &[u8; 512], data: &[u8]) -> Result<()> {
        self.write(header)?; self.write(data)?; self.pad()?; self.mark(); Ok(())
    }

    pub(super) fn copy(&mut self, source: &mut File, mut bytes: u64) -> Result<()> {
        let mut buffer = vec![0; BUFFER];
        while bytes != 0 {
            crate::cancel::check()?;
            let count = buffer.len().min(bytes as usize); source.read_exact(&mut buffer[..count])?; self.bytes(&buffer[..count])?; bytes -= count as u64;
        }
        Ok(())
    }

    pub(super) fn lz4_with(&mut self, header: impl FnOnce(u64) -> Result<[u8; 512]>, source: Blob) -> Result<u64> {
        let at = self.len; let start = at + BLOCK;
        let file = self.file.clone();
        let known = lz4frame::known(&source);
        let header = match known { Some(size) => { self.write(&header(size)?)?; self.mark(); None } None => Some(header) };
        self.len = lz4frame::encode(source, At { file: &file, pos: start, ready: known.and(self.ready.clone()) })?.pos;
        let size = self.len - start;
        match header { Some(header) => write_all_at(&self.file, at, &header(size)?)?, None => if known != Some(size) { bail!("LZ4 member size changed while packing") } }
        self.pad()?; self.mark();
        Ok(size)
    }

    pub fn lz4(&mut self, name: &str, source: Blob, meta: Meta) -> Result<u64> {
        let member = format!("{name}.lz4");
        self.lz4_with(|size| header(&member, size, meta, b'0'), source)
    }

    pub fn member(&mut self, name: &str, source: Blob, meta: Meta, kind: u8) -> Result<()> {
        if !matches!(kind, 0 | b'0' | b'5') { bail!("unsupported tar member type for {name}") }
        let size = source.len()?;
        if kind == b'5' && size != 0 { bail!("directory has data: {name}") }
        self.write(&header(name, size, meta, kind)?)?;
        let mut reader = Window::new(source, 0, size)?; let mut buffer = vec![0; BUFFER];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break }
            self.write(&buffer[..count])?;
        }
        self.pad()?; self.mark();
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.write(&[0; 1024])?;
        let padding = ((RECORD - self.len % RECORD) % RECORD) as usize;
        if padding != 0 { self.write(&vec![0; padding])? }
        self.mark(); drop(self.ready.take());
        let digest = self.hasher.take().context("MD5 worker is missing")?.join().map_err(|_| anyhow::anyhow!("MD5 worker panicked"))??;
        let line = format!("{}  {}\n", hex::encode(digest), self.tar_name);
        self.write(line.as_bytes())?;
        self.file.sync_all()?;
        Ok(())
    }
}
