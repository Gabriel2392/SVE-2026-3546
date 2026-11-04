use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use sha2::{Digest as Sha2Digest, Sha256};

const RESERVED: u64 = 4096;
const GEOMETRY_SIZE: u64 = 4096;
const SECTOR: u64 = 512;
const GEOMETRY_MAGIC: u32 = 0x616c_4467;
const HEADER_MAGIC: u32 = 0x414c_5030;
const PREFIX_LIMIT: u64 = 64 << 20;
pub const PROBE_BYTES: usize = (RESERVED + 2 * GEOMETRY_SIZE) as usize;

fn u16le(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(data.get(at..at + 2).context("short LP field")?.try_into().unwrap()))
}

fn u32le(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(data.get(at..at + 4).context("short LP field")?.try_into().unwrap()))
}

fn u64le(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(data.get(at..at + 8).context("short LP field")?.try_into().unwrap()))
}

fn name(data: &[u8]) -> Result<String> {
    let end = data.iter().position(|&byte| byte == 0).unwrap_or(data.len());
    let name = std::str::from_utf8(&data[..end]).context("LP name is not UTF-8")?;
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) { bail!("invalid LP name") }
    Ok(name.into())
}

#[derive(Clone, Copy)]
struct Geometry { max: u32, slots: u32 }

fn geometry_at(data: &[u8], at: usize) -> Result<Geometry> {
    if u32le(data, at)? != GEOMETRY_MAGIC { bail!("bad LP geometry magic") }
    let size = u32le(data, at + 4)? as usize;
    if !(52..=GEOMETRY_SIZE as usize).contains(&size) { bail!("invalid LP geometry size") }
    let stored = data.get(at + 8..at + 40).context("short LP geometry")?;
    let mut encoded = data.get(at..at + size).context("short LP geometry")?.to_vec();
    encoded[8..40].fill(0);
    if Sha256::digest(encoded).as_slice() != stored { bail!("LP geometry checksum mismatch") }
    let max = u32le(data, at + 40)?;
    let slots = u32le(data, at + 44)?;
    let block = u32le(data, at + 48)?;
    if max == 0 || max as u64 % SECTOR != 0 || !(1..=4).contains(&slots) || block < 512 || !block.is_power_of_two() {
        bail!("invalid LP geometry values")
    }
    Ok(Geometry { max, slots })
}

fn geometry(data: &[u8]) -> Result<Geometry> {
    geometry_at(data, RESERVED as usize).or_else(|_| geometry_at(data, (RESERVED + GEOMETRY_SIZE) as usize))
}

pub fn metadata_bytes(data: &[u8]) -> Result<u64> {
    if data.len() < (RESERVED + GEOMETRY_SIZE + 52) as usize { bail!("short LP geometry prefix") }
    let geometry = geometry(data)?;
    let slots = (geometry.max as u64).checked_mul(geometry.slots as u64).context("LP metadata size overflow")?;
    RESERVED.checked_add((GEOMETRY_SIZE + slots).checked_mul(2).context("LP metadata size overflow")?)
        .filter(|&size| size <= PREFIX_LIMIT).context("LP metadata region is too large")
}

#[derive(Clone, Copy)]
struct Table { offset: u32, count: u32, size: u32 }

fn table(header: &[u8], at: usize, tables_size: u32, minimum: u32) -> Result<Table> {
    let table = Table { offset: u32le(header, at)?, count: u32le(header, at + 4)?, size: u32le(header, at + 8)? };
    if table.count != 0 && table.size < minimum { bail!("LP table entry is too small") }
    let bytes = (table.count as u64).checked_mul(table.size as u64).context("LP table size overflow")?;
    if (table.offset as u64).checked_add(bytes).filter(|&end| end <= tables_size as u64).is_none() { bail!("LP table exceeds metadata") }
    Ok(table)
}

#[derive(Clone, Debug)]
struct Partition { name: String, first: u32, count: u32 }

#[derive(Clone, Copy, Debug)]
struct Extent { sectors: u64, kind: u32, data: u64, source: u32 }

#[derive(Clone, Copy, Debug)]
struct Device { first: u64, size: u64 }

#[derive(Clone, Debug)]
pub struct Metadata {
    partitions: Vec<Partition>,
    extents: Vec<Extent>,
    devices: Vec<Device>,
}

fn parse_copy(data: &[u8], at: usize, max: usize) -> Result<Metadata> {
    let fixed = data.get(at..at + 128).context("short LP header")?;
    if u32le(fixed, 0)? != HEADER_MAGIC || u16le(fixed, 4)? != 10 { bail!("invalid LP metadata header") }
    let header_size = u32le(fixed, 8)? as usize;
    let tables_size = u32le(fixed, 44)? as usize;
    if !(128..=max).contains(&header_size) || header_size.checked_add(tables_size).filter(|&end| end <= max).is_none() {
        bail!("invalid LP metadata sizes")
    }
    let header = data.get(at..at + header_size).context("short LP header")?;
    let mut encoded = header.to_vec();
    encoded[12..44].fill(0);
    if Sha256::digest(encoded).as_slice() != &header[12..44] { bail!("LP header checksum mismatch") }
    let tables = data.get(at + header_size..at + header_size + tables_size).context("short LP tables")?;
    if Sha256::digest(tables).as_slice() != &header[48..80] { bail!("LP tables checksum mismatch") }
    let part_table = table(header, 80, tables_size as u32, 52)?;
    let extent_table = table(header, 92, tables_size as u32, 24)?;
    let device_table = table(header, 116, tables_size as u32, 64)?;
    let mut partitions = Vec::with_capacity(part_table.count as usize);
    let mut unique = BTreeSet::new();
    for index in 0..part_table.count as usize {
        let at = part_table.offset as usize + index * part_table.size as usize;
        let entry = &tables[at..at + part_table.size as usize];
        let name = name(&entry[..36])?;
        if !unique.insert(name.clone()) { bail!("duplicate LP partition {name}") }
        partitions.push(Partition { name, first: u32le(entry, 40)?, count: u32le(entry, 44)? });
    }
    let mut extents = Vec::with_capacity(extent_table.count as usize);
    for index in 0..extent_table.count as usize {
        let at = extent_table.offset as usize + index * extent_table.size as usize;
        let entry = &tables[at..at + extent_table.size as usize];
        extents.push(Extent { sectors: u64le(entry, 0)?, kind: u32le(entry, 8)?, data: u64le(entry, 12)?, source: u32le(entry, 20)? });
    }
    let mut devices = Vec::with_capacity(device_table.count as usize);
    for index in 0..device_table.count as usize {
        let at = device_table.offset as usize + index * device_table.size as usize;
        let entry = &tables[at..at + device_table.size as usize];
        devices.push(Device { first: u64le(entry, 0)?, size: u64le(entry, 16)? });
    }
    if devices.is_empty() { bail!("LP metadata has no block device") }
    Ok(Metadata { partitions, extents, devices })
}

pub fn parse(data: &[u8]) -> Result<Metadata> {
    let geometry = geometry(data)?;
    let base = (RESERVED + 2 * GEOMETRY_SIZE) as usize;
    let span = (geometry.max as usize).checked_mul(geometry.slots as usize).context("LP metadata offset overflow")?;
    parse_copy(data, base, geometry.max as usize).or_else(|_| parse_copy(data, base + span, geometry.max as usize))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan { pub output_name: String, pub size: u64, segments: Vec<Segment> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Segment { pub physical: Option<u64>, pub logical: u64, pub size: u64 }

impl Plan { pub(crate) fn segments(&self) -> &[Segment] { &self.segments } }

impl Metadata {

    pub(crate) fn device_size(&self) -> u64 { self.devices[0].size }


    pub fn plans(&self, requested: Option<&BTreeSet<String>>) -> Result<Vec<Plan>> {
        let by_name = self.partitions.iter().map(|part| (part.name.as_str(), part)).collect::<BTreeMap<_, _>>();
        let pairs = self.partitions.iter().filter_map(|part| part.name.strip_suffix("_a"))
            .filter(|base| by_name.contains_key(&format!("{base}_b")[..])).collect::<BTreeSet<_>>();
        let selected = match requested {
            Some(names) => names.iter().map(|wanted| {
                by_name.get(wanted.as_str()).copied().map(|part| (part, wanted.clone())).or_else(|| {
                    by_name.get(&format!("{wanted}_a")[..]).copied().filter(|_| pairs.contains(wanted.as_str())).map(|part| (part, wanted.clone()))
                }).with_context(|| format!("logical partition not found: {wanted}"))
            }).collect::<Result<Vec<_>>>()?,
            None => self.partitions.iter().filter_map(|part| {
                if let Some(base) = part.name.strip_suffix("_b").filter(|base| pairs.contains(base)) { let _ = base; return None }
                let output = part.name.strip_suffix("_a").filter(|base| pairs.contains(base)).unwrap_or(&part.name).to_owned();
                Some((part, output))
            }).collect(),
        };
        selected.into_iter().map(|(part, output_name)| self.plan(part, output_name)).collect()
    }


    fn plan(&self, part: &Partition, output_name: String) -> Result<Plan> {
        let mut logical = 0u64;
        let mut segments = Vec::new();
        let end = part.first.checked_add(part.count).context("LP extent index overflow")?;
        for index in part.first..end {
            let extent = *self.extents.get(index as usize).with_context(|| format!("LP extent outside table for {}", part.name))?;
            let size = extent.sectors.checked_mul(SECTOR).context("LP extent size overflow")?;
            match extent.kind {
                0 => {
                    if extent.source != 0 { bail!("split LP block devices are unsupported") }
                    let physical = extent.data.checked_mul(SECTOR).context("LP extent offset overflow")?;
                    let device = self.devices[0];
                    if physical < device.first * SECTOR || physical.checked_add(size).filter(|&end| end <= device.size).is_none() {
                        bail!("LP extent outside super device")
                    }
                    segments.push(Segment { physical: Some(physical), logical, size });
                }
                1 => segments.push(Segment { physical: None, logical, size }),
                kind => bail!("unsupported LP extent target {kind}"),
            }
            logical = logical.checked_add(size).context("LP partition size overflow")?;
        }
        Ok(Plan { output_name, size: logical, segments })
    }
}
