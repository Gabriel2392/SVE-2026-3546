use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path};

use anyhow::{bail, Context, Result};
use lz4::{BlockMode, BlockSize, ContentChecksum, EncoderBuilder, liblz4::BlockChecksum};
use md5::{Digest, Md5};

use super::blob::Blob;
use crate::io::Window;

const BLOCK: u64 = 512;
const RECORD: u64 = 20 * BLOCK;

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

struct Count(u64);

impl Write for Count {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_add(data.len() as u64).ok_or(std::io::ErrorKind::FileTooLarge)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

struct Hashed<'a> { file: &'a mut File, hash: &'a mut Md5, len: &'a mut u64 }

impl Write for Hashed<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        crate::cancel::check()?;
        let count = self.file.write(data)?;
        self.hash.update(&data[..count]);
        *self.len = self.len.checked_add(count as u64).ok_or(std::io::ErrorKind::FileTooLarge)?;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> { self.file.flush() }
}

fn lz4<W: Write>(source: Blob, writer: W) -> Result<W> {
    let source_size = source.len()?;
    let mut builder = EncoderBuilder::new();
    let block_size = if source_size <= 1 << 16 { BlockSize::Max64KB } else if source_size <= 1 << 18 { BlockSize::Max256KB } else { BlockSize::Max1MB };
    builder.block_size(block_size).block_mode(BlockMode::Independent).block_checksum(BlockChecksum::NoBlockChecksum)
        .checksum(ContentChecksum::ChecksumEnabled).content_size(source_size);
    let mut encoder = builder.build(writer)?;
    let mut reader = Window::new(source, 0, source_size)?;
    let mut buffer = vec![0; 1 << 20];
    loop {
        crate::cancel::check()?;
        let count = reader.read(&mut buffer)?;
        if count == 0 { break }
        encoder.write_all(&buffer[..count])?;
    }
    let (writer, result) = encoder.finish(); result?;
    Ok(writer)
}

pub struct TarMd5 { file: File, hash: Md5, len: u64, tar_name: String }

impl TarMd5 {
    pub fn create(path: &Path, tar_name: &str) -> Result<Self> {
        let file = OpenOptions::new().write(true).create(true).truncate(true).open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        Ok(Self { file, hash: Md5::new(), len: 0, tar_name: tar_name.to_owned() })
    }

    fn raw(&mut self, data: &[u8]) -> Result<()> {
        let mut writer = Hashed { file: &mut self.file, hash: &mut self.hash, len: &mut self.len };
        writer.write_all(data)?;
        Ok(())
    }

    pub fn lz4(&mut self, name: &str, source: Blob, meta: Meta) -> Result<u64> {
        let member = format!("{name}.lz4");
        let compressed = lz4(source.clone(), Count(0))?.0;
        if compressed == 0 { bail!("LZ4 produced an empty tar member: {member}") }
        self.raw(&header(&member, compressed, meta, b'0')?)?;
        let before = self.len;
        let writer = Hashed { file: &mut self.file, hash: &mut self.hash, len: &mut self.len };
        let writer = lz4(source, writer)?;
        if *writer.len - before != compressed { bail!("non-deterministic LZ4 size for {member}") }
        drop(writer);
        let padding = ((BLOCK - compressed % BLOCK) % BLOCK) as usize;
        if padding != 0 { self.raw(&[0; 512][..padding])? }
        Ok(compressed)
    }

    pub fn member(&mut self, name: &str, source: Blob, meta: Meta, kind: u8) -> Result<()> {
        if !matches!(kind, 0 | b'0' | b'5') { bail!("unsupported tar member type for {name}") }
        let size = source.len()?;
        if kind == b'5' && size != 0 { bail!("directory has data: {name}") }
        self.raw(&header(name, size, meta, kind)?)?;
        let mut reader = Window::new(source, 0, size)?;
        let mut writer = Hashed { file: &mut self.file, hash: &mut self.hash, len: &mut self.len };
        std::io::copy(&mut reader, &mut writer)?;
        let padding = ((BLOCK - size % BLOCK) % BLOCK) as usize;
        if padding != 0 { self.raw(&[0; 512][..padding])? }
        Ok(())
    }


    pub fn finish(mut self) -> Result<()> {
        self.raw(&[0; 1024])?;
        let padding = ((RECORD - self.len % RECORD) % RECORD) as usize;
        if padding != 0 { self.raw(&vec![0; padding])? }
        let digest = hex::encode(self.hash.finalize());
        self.file.write_all(format!("{digest}  {}\n", self.tar_name).as_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}
