use std::{collections::BTreeSet, io::{self, Read, Write}, sync::Arc};

use crc32fast::Hasher;
use flate2::read::DeflateDecoder;

use crate::io::{ReadAt, Region, Window};
use super::safe_path;

const EOCD: u32 = 0x0605_4b50;
const ZIP64_EOCD: u32 = 0x0606_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;
const ENTRY_LIMIT: u64 = 262_144;
const NAME_LIMIT: u64 = 64 << 20;

fn valid_end(data: &[u8], end: usize) -> bool {
    data.len().checked_sub(end).is_some_and(|n| n == 0 || n <= 16 && data[end..].iter().all(|&v| v as usize == n))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn le16(b: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(b.get(at..at + 2).ok_or(io::ErrorKind::UnexpectedEof)?.try_into().unwrap()))
}

fn le32(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(b.get(at..at + 4).ok_or(io::ErrorKind::UnexpectedEof)?.try_into().unwrap()))
}

fn le64(b: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(b.get(at..at + 8).ok_or(io::ErrorKind::UnexpectedEof)?.try_into().unwrap()))
}

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub local_header: u64,
    pub directory: bool,
}

pub struct Zip {
    source: Arc<dyn ReadAt>,
    entries: Vec<ZipEntry>,
    central: u64,
}

struct CheckedReader {
    inner: Box<dyn Read + Send>,
    name: String,
    size: u64,
    crc32: u32,
    read: u64,
    crc: Hasher,
    checked: bool,
}

impl Read for CheckedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        if n != 0 {
            self.read = self.read.checked_add(n as u64).ok_or_else(|| invalid("ZIP output size overflow"))?;
            if self.read > self.size { return Err(invalid(format!("ZIP member expands past declared size: {}", self.name))) }
            self.crc.update(&out[..n]);
        } else if !self.checked {
            self.checked = true;
            if self.read != self.size || self.crc.clone().finalize() != self.crc32 {
                return Err(invalid(format!("ZIP integrity mismatch for {}", self.name)));
            }
        }
        Ok(n)
    }
}

impl Zip {
    pub fn open(source: Arc<dyn ReadAt>) -> io::Result<Self> {
        let len = source.len()?;
        let tail_len = len.min(65_557 + 16) as usize;
        let tail_at = len - tail_len as u64;
        let mut tail = vec![0; tail_len];
        source.read_exact_at(tail_at, &mut tail)?;
        let eocd = (0..tail.len().saturating_sub(21)).rev().find(|&i| le32(&tail, i).ok() == Some(EOCD) &&
            le16(&tail, i + 20).ok().is_some_and(|n| valid_end(&tail, i + 22 + n as usize)))
            .ok_or_else(|| invalid("ZIP end record not found"))?;
        let eocd_at = tail_at.checked_add(eocd as u64).ok_or_else(|| invalid("ZIP end offset overflow"))?;
        if le16(&tail, eocd + 4)? != 0 || le16(&tail, eocd + 6)? != 0 {
            return Err(invalid("multi-disk ZIP is unsupported"));
        }
        let count16 = le16(&tail, eocd + 10)?;
        if le16(&tail, eocd + 8)? != count16 { return Err(invalid("ZIP entry counts disagree")) }
        let size32 = le32(&tail, eocd + 12)?;
        let offset32 = le32(&tail, eocd + 16)?;
        let (count, cd_size, cd_at) = if count16 == u16::MAX || size32 == u32::MAX || offset32 == u32::MAX {
            let locator_at = tail_at.checked_add(eocd as u64).and_then(|v| v.checked_sub(20)).ok_or_else(|| invalid("missing ZIP64 locator"))?;
            let mut locator = [0; 20];
            source.read_exact_at(locator_at, &mut locator)?;
            if le32(&locator, 0)? != ZIP64_LOCATOR || le32(&locator, 4)? != 0 || le32(&locator, 16)? != 1 {
                return Err(invalid("invalid ZIP64 locator"));
            }
            let mut record = [0; 56];
            source.read_exact_at(le64(&locator, 8)?, &mut record)?;
            if le32(&record, 0)? != ZIP64_EOCD || le32(&record, 16)? != 0 || le32(&record, 20)? != 0 {
                return Err(invalid("invalid ZIP64 end record"));
            }
            (le64(&record, 32)?, le64(&record, 40)?, le64(&record, 48)?)
        } else {
            (count16 as u64, size32 as u64, offset32 as u64)
        };
        if cd_at.checked_add(cd_size).filter(|&end| end <= eocd_at).is_none() {
            return Err(invalid("ZIP central directory is out of bounds"));
        }
        let capacity = usize::try_from(count.min(ENTRY_LIMIT)).map_err(|_| invalid("too many ZIP entries"))?;
        if count > ENTRY_LIMIT { return Err(invalid("too many ZIP entries")) }
        let mut entries = Vec::with_capacity(capacity);
        let mut metadata = 0u64;
        let mut unique = BTreeSet::new();
        let mut at = cd_at;
        for _ in 0..count {
            let mut fixed = [0; 46];
            source.read_exact_at(at, &mut fixed)?;
            if le32(&fixed, 0)? != CENTRAL { return Err(invalid("bad ZIP central header")) }
            let flags = le16(&fixed, 8)?;
            if flags & !(0x000e | 0x0800) != 0 || flags & 1 != 0 { return Err(invalid("unsupported ZIP flags")) }
            let name_len = le16(&fixed, 28)? as usize;
            let extra_len = le16(&fixed, 30)? as usize;
            let comment_len = le16(&fixed, 32)? as u64;
            let mut variable = vec![0; name_len + extra_len];
            source.read_exact_at(at + 46, &mut variable)?;
            let name_bytes = &variable[..name_len];
            if flags & (1 << 11) == 0 && !name_bytes.is_ascii() {
                return Err(invalid("non-ASCII legacy ZIP name"));
            }
            let name = std::str::from_utf8(name_bytes).map_err(|_| invalid("invalid ZIP name"))?.to_owned();
            let path = name.strip_suffix('/').unwrap_or(&name);
            safe_path(path)?;
            if !unique.insert(name.clone()) { return Err(invalid(format!("duplicate ZIP member: {name}"))) }
            metadata = metadata.checked_add(46 + variable.len() as u64 + comment_len).filter(|&bytes| bytes <= NAME_LIMIT).ok_or_else(|| invalid("ZIP metadata exceeds limit"))?;
            let mut compressed = le32(&fixed, 20)? as u64;
            let mut size = le32(&fixed, 24)? as u64;
            let mut local = le32(&fixed, 42)? as u64;
            if compressed == u32::MAX as u64 || size == u32::MAX as u64 || local == u32::MAX as u64 {
                let extra = &variable[name_len..];
                let zip64 = find_extra(extra, 1)?.ok_or_else(|| invalid("missing ZIP64 extra field"))?;
                let mut p = 0;
                if size == u32::MAX as u64 { size = le64(zip64, p)?; p += 8; }
                if compressed == u32::MAX as u64 { compressed = le64(zip64, p)?; p += 8; }
                if local == u32::MAX as u64 { local = le64(zip64, p)?; }
            }
            let method = le16(&fixed, 10)?;
            if !matches!(method, 0 | 8) { return Err(invalid(format!("unsupported ZIP method {method}"))) }
            if method == 0 && flags & 6 != 0 { return Err(invalid("stored ZIP member has deflate flags")) }
            entries.push(ZipEntry { directory: name.ends_with('/'), name, method, flags, crc32: le32(&fixed, 16)?, compressed_size: compressed, size, local_header: local });
            at = at.checked_add(46 + variable.len() as u64 + comment_len).ok_or_else(|| invalid("ZIP offset overflow"))?;
        }
        if at != cd_at + cd_size { return Err(invalid("ZIP central directory size mismatch")) }
        let zip = Self { source, entries, central: cd_at };
        let mut ranges = zip.entries.iter().filter(|entry| !entry.directory).map(|entry| {
            let data = zip.data_offset(entry)?;
            let end = data.checked_add(entry.compressed_size).ok_or_else(|| invalid("ZIP entry range overflow"))?;
            Ok((entry.local_header, end, entry.name.as_str()))
        }).collect::<io::Result<Vec<_>>>()?;
        ranges.sort_by_key(|range| range.0);
        for pair in ranges.windows(2) {
            if pair[0].1 > pair[1].0 { return Err(invalid(format!("overlapping ZIP members: {} and {}", pair[0].2, pair[1].2))) }
        }
        Ok(zip)
    }

    pub fn entries(&self) -> &[ZipEntry] { &self.entries }

    pub fn exact(&self, name: &str) -> io::Result<&ZipEntry> {
        self.find_exact(name)?.ok_or_else(|| invalid(format!("ZIP member not found: {name}")))
    }

    pub fn find_exact(&self, name: &str) -> io::Result<Option<&ZipEntry>> {
        let mut found = self.entries.iter().filter(|entry| entry.name == name);
        let Some(entry) = found.next() else { return Ok(None) };
        if found.next().is_some() { return Err(invalid(format!("duplicate ZIP member: {name}"))) }
        Ok(Some(entry))
    }

    fn data_offset(&self, entry: &ZipEntry) -> io::Result<u64> {
        if entry.directory { return Err(invalid("cannot read a ZIP directory")) }
        let mut local = [0; 30];
        self.source.read_exact_at(entry.local_header, &mut local)?;
        let flags = le16(&local, 6)?;
        if le32(&local, 0)? != LOCAL || le16(&local, 8)? != entry.method || flags != entry.flags || flags & 1 != 0 {
            return Err(invalid("ZIP local header disagrees with central directory"));
        }
        let name_len = le16(&local, 26)? as usize;
        let extra_len = le16(&local, 28)? as u64;
        let mut name = vec![0; name_len];
        self.source.read_exact_at(entry.local_header + 30, &mut name)?;
        if name != entry.name.as_bytes() { return Err(invalid("ZIP local name disagrees with central directory")) }
        let data = entry.local_header.checked_add(30 + name_len as u64 + extra_len).ok_or_else(|| invalid("ZIP offset overflow"))?;
        let source_len = self.source.len()?;
        if entry.local_header >= self.central || data.checked_add(entry.compressed_size).filter(|&v| v <= source_len && v <= self.central).is_none() {
            return Err(invalid("ZIP entry is out of bounds"));
        }
        Ok(data)
    }

    pub fn stored_region(&self, entry: &ZipEntry) -> io::Result<Region> {
        if entry.method != 0 || entry.compressed_size != entry.size {
            return Err(invalid(format!("ZIP member is not stored: {}", entry.name)));
        }
        self.compressed_region(entry)
    }

    fn compressed_region(&self, entry: &ZipEntry) -> io::Result<Region> {
        Region::new(self.source.clone(), self.data_offset(entry)?, entry.compressed_size)
    }

    pub fn reader(&self, entry: &ZipEntry) -> io::Result<Box<dyn Read + Send>> {
        let data = self.data_offset(entry)?;
        let window = Window::new(self.source.clone(), data, entry.compressed_size)?;
        let inner: Box<dyn Read + Send> = match entry.method {
            0 => Box::new(window),
            8 => Box::new(DeflateDecoder::new(window)),
            method => return Err(invalid(format!("unsupported ZIP method {method}"))),
        };
        Ok(Box::new(CheckedReader { inner, name: entry.name.clone(), size: entry.size, crc32: entry.crc32, read: 0, crc: Hasher::new(), checked: false }))
    }

    pub fn copy<W: Write>(&self, entry: &ZipEntry, out: &mut W) -> io::Result<u64> {
        let mut reader = self.reader(entry)?;
        let mut total = 0u64;
        let mut buf = vec![0; 4 << 20];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 { break }
            out.write_all(&buf[..n])?;
            total += n as u64;
        }
        Ok(total)
    }

    pub fn verify(&self, entry: &ZipEntry) -> io::Result<()> {
        io::copy(&mut self.reader(entry)?, &mut io::sink())?;
        Ok(())
    }
}

fn find_extra(mut extra: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
    while !extra.is_empty() {
        if extra.len() < 4 { return Err(invalid("truncated ZIP extra field")) }
        let tag = le16(extra, 0)?;
        let len = le16(extra, 2)? as usize;
        let value = extra.get(4..4 + len).ok_or_else(|| invalid("truncated ZIP extra value"))?;
        if tag == wanted { return Ok(Some(value)) }
        extra = &extra[4 + len..];
    }
    Ok(None)
}
