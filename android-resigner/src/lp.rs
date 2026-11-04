use std::{collections::{BTreeMap, BTreeSet}, io, sync::Arc};

use anyhow::{bail, Context, Result};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::io::{Bytes, ReadAt};

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

fn set32(data: &mut [u8], at: usize, value: u32) -> Result<()> {
    data.get_mut(at..at + 4).context("short LP field")?.copy_from_slice(&value.to_le_bytes()); Ok(())
}

fn set64(data: &mut [u8], at: usize, value: u64) -> Result<()> {
    data.get_mut(at..at + 8).context("short LP field")?.copy_from_slice(&value.to_le_bytes()); Ok(())
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
struct Device { first: u64, size: u64, alignment: u32, offset: u32 }

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
        devices.push(Device { first: u64le(entry, 0)?, alignment: u32le(entry, 8)?, offset: u32le(entry, 12)?, size: u64le(entry, 16)? });
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

struct RawSuper {
    len: u64,
    pieces: Vec<(u64, Arc<dyn ReadAt>)>,
}

impl ReadAt for RawSuper {
    fn len(&self) -> io::Result<u64> { Ok(self.len) }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || output.is_empty() { return Ok(0) }
        let count = output.len().min(usize::try_from(self.len - offset).unwrap_or(usize::MAX));
        output[..count].fill(0);
        let end = offset + count as u64;
        for (start, source) in &self.pieces {
            let source_len = source.len()?;
            let source_end = start.checked_add(source_len).ok_or(io::ErrorKind::InvalidInput)?;
            let left = offset.max(*start);
            let right = end.min(source_end);
            if left >= right { continue }
            let out_at = (left - offset) as usize;
            source.read_exact_at(left - start, &mut output[out_at..out_at + (right - left) as usize])?;
        }
        Ok(count)
    }
}

pub struct BuiltSuper {
    pub prefix: Vec<u8>,
    pub metadata: Metadata,
    pub raw: Arc<dyn ReadAt>,
}

fn aligned(value: u64, alignment: u32, offset: u32) -> Result<u64> {
    if alignment == 0 { return Ok(value) }
    let alignment = alignment as u64;
    let offset = offset as u64;
    if !alignment.is_power_of_two() || offset >= alignment { bail!("invalid LP block-device alignment") }
    let delta = (offset + alignment - value % alignment) % alignment;
    value.checked_add(delta).context("LP extent alignment overflow")
}

pub fn build_super(empty: &[u8], expected_groups: &BTreeMap<String, u64>, targets: Vec<(String, String, u64, Arc<dyn ReadAt>)>) -> Result<BuiltSuper> {
    if empty.len() < GEOMETRY_SIZE as usize + 128 { bail!("compact LP metadata is too short") }
    let geometry = geometry_at(empty, 0)?;
    let header_at = GEOMETRY_SIZE as usize;
    let fixed = empty.get(header_at..header_at + 128).context("short compact LP header")?;
    if u32le(fixed, 0)? != HEADER_MAGIC || u16le(fixed, 4)? != 10 { bail!("invalid compact LP metadata header") }
    let header_size = u32le(fixed, 8)? as usize;
    let tables_size = u32le(fixed, 44)? as usize;
    let header = empty.get(header_at..header_at + header_size).context("short compact LP header")?;
    let tables = empty.get(header_at + header_size..header_at + header_size + tables_size).context("short compact LP tables")?;
    let mut checked = header.to_vec(); checked[12..44].fill(0);
    if Sha256::digest(checked).as_slice() != &header[12..44] || Sha256::digest(tables).as_slice() != &header[48..80] {
        bail!("compact LP metadata checksum mismatch")
    }
    let part_table = table(header, 80, tables_size as u32, 52)?;
    let extent_table = table(header, 92, tables_size as u32, 24)?;
    let group_table = table(header, 104, tables_size as u32, 48)?;
    let device_table = table(header, 116, tables_size as u32, 64)?;
    if extent_table.count != 0 || device_table.count != 1 { bail!("unsupported compact LP layout") }
    let mut template_parts = BTreeMap::new();
    for index in 0..part_table.count as usize {
        let at = part_table.offset as usize + index * part_table.size as usize;
        let entry = tables.get(at..at + part_table.size as usize).context("short compact LP partition")?;
        let part_name = name(&entry[..36])?;
        if template_parts.insert(part_name.clone(), (entry.to_vec(), u32le(entry, 48)?)).is_some() { bail!("duplicate compact LP partition {part_name}") }
    }
    let mut groups = Vec::with_capacity(group_table.count as usize);
    for index in 0..group_table.count as usize {
        let at = group_table.offset as usize + index * group_table.size as usize;
        let entry = tables.get(at..at + group_table.size as usize).context("short compact LP group")?.to_vec();
        groups.push((name(&entry[..36])?, u64le(&entry, 40)?, entry));
    }
    let device_at = device_table.offset as usize;
    let device_raw = tables.get(device_at..device_at + device_table.size as usize).context("short compact LP block device")?.to_vec();
    let device = Device { first: u64le(&device_raw, 0)?, alignment: u32le(&device_raw, 8)?, offset: u32le(&device_raw, 12)?, size: u64le(&device_raw, 16)? };
    let prefix_size = RESERVED.checked_add((GEOMETRY_SIZE + geometry.max as u64 * geometry.slots as u64).checked_mul(2).context("LP metadata size overflow")?).context("LP metadata size overflow")?;
    if device.size > 16 << 30 || device.first.checked_mul(SECTOR).is_none_or(|first| first < prefix_size || first >= device.size) { bail!("invalid compact LP block device") }
    for (name, maximum) in expected_groups {
        let found = groups.iter().find(|(group, _, _)| group == name).with_context(|| format!("compact LP metadata has no group {name}"))?;
        if found.1 != *maximum { bail!("LP group {name} maximum does not match dynamic layout") }
    }
    for (name, maximum, _) in &groups {
        if *maximum != 0 && !expected_groups.contains_key(name) { bail!("unexpected LP group {name}") }
    }
    let wanted = targets.iter().map(|(name, _, _, _)| name.clone()).collect::<BTreeSet<_>>();
    if wanted.len() != targets.len() || wanted != template_parts.keys().cloned().collect() { bail!("logical targets do not match compact LP partitions") }
    let mut group_usage = vec![0u64; groups.len()];
    let mut part_data = Vec::with_capacity(targets.len() * part_table.size as usize);
    let mut extent_data = Vec::with_capacity(targets.len() * 24);
    let mut pieces = Vec::with_capacity(targets.len() + 1);
    let mut physical = device.first.checked_mul(SECTOR).context("LP first sector overflow")?;
    for (index, (part_name, expected_group, size, image)) in targets.into_iter().enumerate() {
        if size == 0 || size % SECTOR != 0 || image.len()? != size { bail!("invalid logical image size for {part_name}") }
        let (mut part, group) = template_parts.remove(&part_name).unwrap();
        let group_at = usize::try_from(group).context("LP group index overflow")?;
        if groups.get(group_at).map(|group| group.0.as_str()) != Some(expected_group.as_str()) { bail!("LP partition {part_name} is in the wrong group") }
        let usage = group_usage.get_mut(group_at).context("LP partition has invalid group")?;
        *usage = usage.checked_add(size).context("LP group size overflow")?;
        set32(&mut part, 40, index as u32)?; set32(&mut part, 44, 1)?;
        part_data.extend_from_slice(&part);
        physical = aligned(physical, device.alignment, device.offset)?;
        let end = physical.checked_add(size).context("LP image allocation overflow")?;
        if end > device.size { bail!("logical images exceed super device") }
        let mut extent = vec![0; 24]; set64(&mut extent, 0, size / SECTOR)?; set32(&mut extent, 8, 0)?;
        set64(&mut extent, 12, physical / SECTOR)?; set32(&mut extent, 20, 0)?;
        extent_data.extend_from_slice(&extent); pieces.push((physical, image)); physical = end;
    }
    for (index, (group_name, maximum, _)) in groups.iter().enumerate() {
        if *maximum != 0 && group_usage[index] > *maximum { bail!("LP group {group_name} exceeds its maximum size") }
    }
    let group_data = groups.into_iter().flat_map(|(_, _, raw)| raw).collect::<Vec<_>>();
    let mut encoded_tables = Vec::with_capacity(part_data.len() + extent_data.len() + group_data.len() + device_raw.len());
    encoded_tables.extend_from_slice(&part_data); let extent_offset = encoded_tables.len(); encoded_tables.extend_from_slice(&extent_data);
    let group_offset = encoded_tables.len(); encoded_tables.extend_from_slice(&group_data); let device_offset = encoded_tables.len(); encoded_tables.extend_from_slice(&device_raw);
    let mut encoded_header = header.to_vec();
    set32(&mut encoded_header, 44, encoded_tables.len() as u32)?;
    set32(&mut encoded_header, 80, 0)?; set32(&mut encoded_header, 84, part_data.len() as u32 / part_table.size)?; set32(&mut encoded_header, 88, part_table.size)?;
    set32(&mut encoded_header, 92, extent_offset as u32)?; set32(&mut encoded_header, 96, extent_data.len() as u32 / 24)?; set32(&mut encoded_header, 100, 24)?;
    set32(&mut encoded_header, 104, group_offset as u32)?; set32(&mut encoded_header, 108, group_data.len() as u32 / group_table.size)?; set32(&mut encoded_header, 112, group_table.size)?;
    set32(&mut encoded_header, 116, device_offset as u32)?; set32(&mut encoded_header, 120, 1)?; set32(&mut encoded_header, 124, device_table.size)?;
    encoded_header[12..44].fill(0); encoded_header[48..80].copy_from_slice(Sha256::digest(&encoded_tables).as_slice());
    let header_hash = Sha256::digest(&encoded_header); encoded_header[12..44].copy_from_slice(header_hash.as_slice());
    let metadata_len = encoded_header.len().checked_add(encoded_tables.len()).context("LP metadata size overflow")?;
    if metadata_len > geometry.max as usize { bail!("LP metadata exceeds geometry maximum") }
    let mut slot = vec![0; geometry.max as usize]; slot[..encoded_header.len()].copy_from_slice(&encoded_header);
    slot[encoded_header.len()..metadata_len].copy_from_slice(&encoded_tables);
    let mut prefix = vec![0; prefix_size as usize];
    prefix[RESERVED as usize..(RESERVED + GEOMETRY_SIZE) as usize].copy_from_slice(&empty[..GEOMETRY_SIZE as usize]);
    prefix[(RESERVED + GEOMETRY_SIZE) as usize..(RESERVED + 2 * GEOMETRY_SIZE) as usize].copy_from_slice(&empty[..GEOMETRY_SIZE as usize]);
    let primary = (RESERVED + 2 * GEOMETRY_SIZE) as usize;
    let span = geometry.max as usize * geometry.slots as usize;
    for index in 0..geometry.slots as usize {
        let at = primary + index * geometry.max as usize; prefix[at..at + slot.len()].copy_from_slice(&slot);
        let at = primary + span + index * geometry.max as usize; prefix[at..at + slot.len()].copy_from_slice(&slot);
    }
    let metadata = parse(&prefix)?;
    pieces.insert(0, (0, Arc::new(Bytes(prefix.clone()))));
    let raw: Arc<dyn ReadAt> = Arc::new(RawSuper { len: device.size, pieces });
    Ok(BuiltSuper { prefix, metadata, raw })
}
