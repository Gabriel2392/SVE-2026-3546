use std::{io, sync::Arc};

use crate::io::{ReadAt, Region};

use super::safe_path;

const BLOCK: usize = 512;
const META_LIMIT: u64 = 1 << 20;
const ENTRY_LIMIT: usize = 262_144;
const NAME_LIMIT: usize = 64 << 20;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn number(field: &[u8]) -> io::Result<u64> {
    if field.first().copied().unwrap_or(0) & 0x80 != 0 {
        if field[0] & 0x40 != 0 { return Err(invalid("negative tar number")) }
        return field.iter().enumerate().try_fold(0u64, |n, (i, &b)| n.checked_mul(256)
            .and_then(|n| n.checked_add((if i == 0 { b & 0x7f } else { b }) as u64)).ok_or_else(|| invalid("tar number overflow")));
    }
    let mut value = 0u64;
    for &b in field.iter().skip_while(|&&b| b == 0 || b == b' ') {
        if b == 0 || b == b' ' { break }
        if !(b'0'..=b'7').contains(&b) { return Err(invalid("invalid tar octal")) }
        value = value.checked_mul(8).and_then(|v| v.checked_add((b - b'0') as u64)).ok_or_else(|| invalid("tar number overflow"))?;
    }
    Ok(value)
}

fn text(field: &[u8]) -> io::Result<String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    Ok(std::str::from_utf8(&field[..end]).map_err(|_| invalid("invalid UTF-8 tar path"))?.trim_end().into())
}

fn path(header: &[u8; BLOCK]) -> io::Result<String> {
    let name = text(&header[..100])?;
    let prefix = text(&header[345..500])?;
    Ok(if prefix.is_empty() { name } else { format!("{prefix}/{name}") })
}

fn checksum(header: &[u8; BLOCK]) -> io::Result<()> {
    let expected = number(&header[148..156])?;
    let actual: u64 = header.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { b' ' } else { b }).map(u64::from).sum();
    if expected != actual { Err(invalid("tar header checksum mismatch")) } else { Ok(()) }
}

fn pax_path(data: &[u8]) -> io::Result<Option<String>> {
    let text = std::str::from_utf8(data).map_err(|_| invalid("invalid PAX metadata"))?;
    let mut at = 0;
    let mut path = None;
    while at < text.len() {
        let space = text[at..].find(' ').ok_or_else(|| invalid("invalid PAX record"))? + at;
        let len: usize = text[at..space].parse().map_err(|_| invalid("invalid PAX length"))?;
        let end = at.checked_add(len).filter(|&v| v <= text.len()).ok_or_else(|| invalid("truncated PAX record"))?;
        if end <= space + 1 || text.as_bytes()[end - 1] != b'\n' { return Err(invalid("invalid PAX record length")) }
        let value = &text[space + 1..end];
        if let Some(v) = value.strip_prefix("path=") { path = Some(v.trim_end_matches('\n').into()) }
        at = end;
    }
    Ok(path)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedTarEntry {
    pub name: String,
    pub size: u64,
    pub kind: u8,
    data: u64,
}

pub struct TarIndex {
    source: Arc<dyn ReadAt>,
    entries: Vec<IndexedTarEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TarMetadata {
    pub mode: u32,
    pub mtime: u64,
}

impl TarIndex {
    pub fn open(source: Arc<dyn ReadAt>) -> io::Result<Self> {
        let len = source.len()?;
        let mut entries = Vec::new();
        let mut at = 0u64;
        let mut name_bytes = 0usize;
        let mut override_name = None;
        loop {
            if at.checked_add(BLOCK as u64).filter(|&end| end <= len).is_none() {
                return Err(invalid("tar ended before end marker"));
            }
            let mut header = [0; BLOCK];
            source.read_exact_at(at, &mut header)?;
            if header.iter().all(|&b| b == 0) { break }
            checksum(&header)?;
            let size = number(&header[124..136])?;
            let kind = header[156];
            let data = at.checked_add(BLOCK as u64).ok_or_else(|| invalid("tar offset overflow"))?;
            let padded = size.checked_add(BLOCK as u64 - 1).map(|n| n / BLOCK as u64 * BLOCK as u64)
                .ok_or_else(|| invalid("tar size overflow"))?;
            at = data.checked_add(padded).filter(|&end| end <= len).ok_or_else(|| invalid("tar member exceeds source"))?;
            if kind == b'x' || kind == b'g' || kind == b'L' {
                if size > META_LIMIT { return Err(invalid("tar metadata entry too large")) }
                let mut metadata = vec![0; size as usize];
                source.read_exact_at(data, &mut metadata)?;
                override_name = if kind == b'L' { Some(text(&metadata)?.trim_end_matches('\n').into()) } else { pax_path(&metadata)?.or(override_name) };
                continue;
            }
            let name = override_name.take().unwrap_or(path(&header)?);
            safe_path(&name)?;
            name_bytes = name_bytes.checked_add(name.len()).filter(|&bytes| bytes <= NAME_LIMIT).ok_or_else(|| invalid("tar names exceed metadata limit"))?;
            if entries.len() >= ENTRY_LIMIT { return Err(invalid("too many tar entries")) }
            entries.push(IndexedTarEntry { name, size, kind, data });
        }
        Ok(Self { source, entries })
    }

    pub fn entries(&self) -> &[IndexedTarEntry] { &self.entries }

    pub fn metadata(&self, entry: &IndexedTarEntry) -> io::Result<TarMetadata> {
        let at = entry.data.checked_sub(BLOCK as u64).ok_or_else(|| invalid("tar member has no header"))?;
        let mut header = [0; BLOCK]; self.source.read_exact_at(at, &mut header)?; checksum(&header)?;
        Ok(TarMetadata { mode: number(&header[100..108])? as u32, mtime: number(&header[136..148])? })
    }

    pub fn region(&self, entry: &IndexedTarEntry) -> io::Result<Region> {
        if !matches!(entry.kind, 0 | b'0' | b'5') || entry.kind == b'5' && entry.size != 0 {
            return Err(invalid("tar member data is unsupported"))
        }
        Region::new(self.source.clone(), entry.data, entry.size)
    }
}
