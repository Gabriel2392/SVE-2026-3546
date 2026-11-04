use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};

use super::{blob::{self, Blob}, config::Ramdisk, crypto::Keys, ramdisk};

const MARKER: &[u8] = b"SEANDROIDENFORCE";

fn u32le(data: &[u8], at: usize) -> Result<u32> { Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated boot image u32")?.try_into().unwrap())) }
fn u64le(data: &[u8], at: usize) -> Result<u64> { Ok(u64::from_le_bytes(data.get(at..at + 8).context("truncated boot image u64")?.try_into().unwrap())) }
fn set32(data: &mut [u8], at: usize, value: usize) -> Result<()> { data.get_mut(at..at + 4).context("truncated boot image u32")?.copy_from_slice(&u32::try_from(value).context("boot image component exceeds 4 GiB")?.to_le_bytes()); Ok(()) }
fn set64(data: &mut [u8], at: usize, value: usize) -> Result<()> { data.get_mut(at..at + 8).context("truncated boot image u64")?.copy_from_slice(&u64::try_from(value).context("boot image component is too large")?.to_le_bytes()); Ok(()) }
fn align(value: usize, page: usize) -> Result<usize> { value.checked_add(page - 1).map(|value| value / page * page).context("boot image size overflow") }

fn add(left: usize, right: usize) -> Result<usize> { left.checked_add(right).context("boot image size overflow") }

fn component<'a>(data: &'a [u8], at: usize, size: usize, name: &str) -> Result<&'a [u8]> {
    data.get(at..add(at, size)?).with_context(|| format!("truncated Android boot {name}"))
}

fn append(out: &mut Vec<u8>, data: &[u8], page: usize) -> Result<()> {
    out.extend_from_slice(data);
    out.resize(align(out.len(), page)?, 0);
    Ok(())
}

fn normal(data: &[u8], rules: &Ramdisk, keys: &Keys, description: &str) -> Result<Vec<u8>> {
    if data.len() < 44 || &data[..8] != b"ANDROID!" { bail!("invalid Android boot image") }
    let version = u32le(data, 40)?; if version > 2 { bail!("ramdisk repacking only supports Android boot headers v0-v2 here") }
    let header_size = match version { 0 => 1632, 1 => 1648, _ => 1660 };
    let page = u32le(data, 36)? as usize;
    if page < header_size || !page.is_power_of_two() || page > data.len() { bail!("invalid Android boot page size") }
    if version > 0 && u32le(data, 1644)? as usize != header_size { bail!("unexpected Android boot header size") }
    let kernel_size = u32le(data, 8)? as usize; let ramdisk_size = u32le(data, 16)? as usize; let second_size = u32le(data, 24)? as usize;
    let recovery_size = if version > 0 { u32le(data, 1632)? as usize } else { 0 }; let dtb_size = if version > 1 { u32le(data, 1648)? as usize } else { 0 };
    let kernel_at = page; let ramdisk_at = align(add(kernel_at, kernel_size)?, page)?;
    let second_at = align(add(ramdisk_at, ramdisk_size)?, page)?;
    let recovery_at = align(add(second_at, second_size)?, page)?;
    let dtb_at = align(add(recovery_at, recovery_size)?, page)?;
    if version > 0 && recovery_size != 0 && u64le(data, 1636)? != recovery_at as u64 { bail!("invalid recovery_dtbo offset") }
    let kernel = component(data, kernel_at, kernel_size, "kernel")?;
    let patched = ramdisk::patch(component(data, ramdisk_at, ramdisk_size, "ramdisk")?, rules, keys, description)?;
    if patched.signed == 0 { return Ok(data.to_vec()) }
    let ramdisk = patched.data;
    let second = component(data, second_at, second_size, "second stage")?;
    let recovery = component(data, recovery_at, recovery_size, "recovery_dtbo")?;
    let dtb = component(data, dtb_at, dtb_size, "DTB")?;
    let mut header = data[..page].to_vec();
    set32(&mut header, 16, ramdisk.len())?;
    if version > 0 {
        let recovery_offset = align(add(align(add(align(add(page, kernel.len())?, page)?, ramdisk.len())?, page)?, second.len())?, page)?;
        set64(&mut header, 1636, if recovery_size == 0 { 0 } else { recovery_offset })?;
    }
    let mut hash = Sha1::new();
    for piece in [kernel, &ramdisk, second] { hash.update(piece); hash.update((piece.len() as u32).to_le_bytes()) }
    if version > 0 { hash.update(recovery); hash.update((recovery.len() as u32).to_le_bytes()) }
    if version > 1 { hash.update(dtb); hash.update((dtb.len() as u32).to_le_bytes()) }
    header[576..608].fill(0); header[576..596].copy_from_slice(&hash.finalize());
    let mut out = header; append(&mut out, kernel, page)?; append(&mut out, &ramdisk, page)?; append(&mut out, second, page)?;
    if version > 0 { append(&mut out, recovery, page)? } if version > 1 { append(&mut out, dtb, page)? }
    Ok(out)
}

fn vendor(data: &[u8], rules: &Ramdisk, keys: &Keys, description: &str) -> Result<Vec<u8>> {
    if data.len() < 2128 || &data[..8] != b"VNDRBOOT" || u32le(data, 8)? != 4 { bail!("only Android vendor_boot v4 is supported") }
    let page = u32le(data, 12)? as usize; let header_size = u32le(data, 2096)? as usize;
    if page < 512 || !page.is_power_of_two() || !(2128..=page * 16).contains(&header_size) { bail!("invalid vendor_boot geometry") }
    let ramdisk_size = u32le(data, 24)? as usize; let dtb_size = u32le(data, 2100)? as usize; let table_size = u32le(data, 2112)? as usize;
    let entries = u32le(data, 2116)? as usize; let entry_size = u32le(data, 2120)? as usize; let bootconfig_size = u32le(data, 2124)? as usize;
    if entry_size < 108 || table_size != entries.checked_mul(entry_size).context("vendor ramdisk table overflow")? { bail!("invalid vendor ramdisk table") }
    let ramdisk_at = align(header_size, page)?; let dtb_at = align(add(ramdisk_at, ramdisk_size)?, page)?; let table_at = align(add(dtb_at, dtb_size)?, page)?; let bootconfig_at = align(add(table_at, table_size)?, page)?;
    let table = component(data, table_at, table_size, "vendor ramdisk table")?; let mut fragments = Vec::with_capacity(entries);
    let mut offsets = Vec::with_capacity(entries); let mut table_names = Vec::with_capacity(entries);
    for index in 0..entries {
        let entry = &table[index * entry_size..(index + 1) * entry_size]; let size = u32le(entry, 0)? as usize; let offset = u32le(entry, 4)? as usize;
        if size == 0 { bail!("empty vendor ramdisk fragment {index}") }
        fragments.push(component(data, add(ramdisk_at, offset)?, size, "vendor ramdisk fragment")?.to_vec()); offsets.push(offset);
        let raw = &entry[12..44]; let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
        table_names.push(std::str::from_utf8(&raw[..end]).ok().map(str::to_owned));
    }
    let mut order = (0..entries).collect::<Vec<_>>(); order.sort_by_key(|&index| offsets[index]);
    let mut original_end = 0usize;
    for &index in &order {
        if offsets[index] != original_end { bail!("vendor ramdisk fragments have gaps or overlap") }
        original_end = add(original_end, fragments[index].len())?;
    }
    if original_end != ramdisk_size { bail!("vendor ramdisk table does not cover the ramdisk section") }

    let mut selected = BTreeSet::new();
    if rules.discover_firmware { selected.extend(0..entries) } else {
        for name in &rules.names {
            let suffix = name.strip_prefix("vendor_ramdisk").or_else(|| name.strip_prefix("ramdisk"));
            if let Some(index) = suffix.and_then(|index| index.parse::<usize>().ok()).filter(|&index| index < entries) { selected.insert(index); }
            for (index, stored) in table_names.iter().enumerate() { if stored.as_deref() == Some(name) { selected.insert(index); } }
        }
        if selected.is_empty() { bail!("none of the configured vendor ramdisk names exists") }
    }

    let mut found = BTreeSet::new(); let mut signed = 0usize;
    for &index in &selected {
        let label = table_names[index].as_deref().filter(|name| !name.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("vendor_ramdisk{index:02}"));
        let result = ramdisk::patch_fragment(&fragments[index], rules, keys, &format!("{description}:{label}"))?;
        signed = signed.checked_add(result.signed).context("too many signed ramdisk files")?;
        found.extend(result.found); fragments[index] = result.data;
    }
    ramdisk::finish(rules, &found, description)?;
    if signed == 0 { return Ok(data.to_vec()) }

    let mut combined = Vec::new(); let mut new_offsets = vec![0usize; entries];
    for &index in &order { new_offsets[index] = combined.len(); combined.extend_from_slice(&fragments[index]); }
    let mut header = data[..ramdisk_at].to_vec(); set32(&mut header, 24, combined.len())?;
    let mut updated_table = table.to_vec(); let mut total = 0;
    for (index, fragment) in fragments.iter().enumerate() {
        let entry = &mut updated_table[index * entry_size..(index + 1) * entry_size]; set32(entry, 0, fragment.len())?; set32(entry, 4, new_offsets[index])?; total = add(total, fragment.len())?;
    }
    if total != combined.len() { bail!("vendor ramdisk size accounting mismatch") }
    let dtb = component(data, dtb_at, dtb_size, "vendor_boot DTB")?; let bootconfig = component(data, bootconfig_at, bootconfig_size, "vendor bootconfig")?;
    let mut out = header; out.extend_from_slice(&combined); out.resize(align(out.len(), page)?, 0);
    append(&mut out, dtb, page)?; append(&mut out, &updated_table, page)?; append(&mut out, bootconfig, page)?; Ok(out)
}

pub fn repack(source: Blob, rules: &Ramdisk, keys: &Keys, description: &str) -> Result<Blob> {
    let mut data = blob::read_all(source.as_ref(), 512 << 20)?; let marker = data.ends_with(MARKER); if marker { data.truncate(data.len() - MARKER.len()) }
    let mut out = if data.starts_with(b"ANDROID!") { normal(&data, rules, keys, description)? } else if data.starts_with(b"VNDRBOOT") { vendor(&data, rules, keys, description)? } else { bail!("unsupported boot image magic") };
    if marker { out.extend_from_slice(MARKER) } Ok(blob::bytes(out))
}
