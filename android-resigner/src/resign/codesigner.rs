use anyhow::{bail, Context, Result};
use p384::ecdsa::SigningKey;
use sha2_10::{Digest, Sha512};

use super::{blob::{self, Blob}, crypto::{self, Keys}};
const MARKER: &[u8] = b"SignerVer03";
const INFO: usize = 0x100;
const NAME: usize = 0x9c;
const NAME_LEN: usize = 0x10;
const HEADER: usize = 0x10;
const FOOTER: usize = 0x210;
const EXCLUDED: usize = 0x200;
const SIGNATURE: usize = 136;
pub(super) const NORMAL: usize = INFO + FOOTER;
const SPARSE_HEADER: usize = 28;
const CHUNK_HEADER: usize = 12;
const SPARSE_INFO: u64 = 0x328;
const SPARSE_SIGNATURE: u64 = 0x38;

#[derive(Clone)]
pub struct Template { info: Vec<u8>, footer: Vec<u8> }

pub(super) fn same_build_family(base: &str, candidate: &str) -> bool {
    if candidate == base { return true }
    candidate.strip_prefix(base).is_some_and(|suffix| {
        suffix.starts_with('_') && suffix.len() > 1
            && suffix[1..].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

impl Template {
    pub(super) fn key_type(&self) -> Result<u32> {
        let value = le32(&self.footer, 8)?;
        if value > 1 { bail!("invalid stock ST2 key type {value}") }
        Ok(value)
    }

    fn validate_footer(footer: &[u8]) -> Result<()> {
        if footer.len() != FOOTER { bail!("invalid CodeSigner v5 footer size") }
        let key_type = le32(footer, 8)?;
        let key_index = le32(footer, 12)?;
        let signature = &footer[HEADER..HEADER + SIGNATURE];
        if le32(footer, 4)? != 4 || key_type > 1 || key_index == 0
            || signature[..20].iter().any(|&byte| byte != 0)
            || signature[68..88].iter().any(|&byte| byte != 0)
            || signature[20..68].iter().all(|&byte| byte == 0)
            || signature[88..136].iter().all(|&byte| byte == 0) {
            bail!("invalid CodeSigner v5 fields")
        }
        Ok(())
    }

    pub(super) fn from_parts(info: &[u8], footer: &[u8]) -> Result<Self> {
        if info.len() != INFO || !info.starts_with(MARKER) { bail!("invalid SignerVer03 metadata") }
        Self::validate_footer(footer)?;
        Ok(Self { info: info.to_vec(), footer: footer.to_vec() })
    }

    pub(super) fn from_trailer(data: &[u8]) -> Result<Self> {
        if data.len() != NORMAL { bail!("invalid CodeSigner v5 trailer") }
        Self::from_parts(&data[..INFO], &data[INFO..])
    }

    pub(super) fn from_sparse_seed(block: &[u8]) -> Result<Self> {
        if block.len() < 0x400 { bail!("sparse CodeSigner seed is smaller than 0x400 bytes") }
        Self::from_parts(&block[0x300..0x400], &block[..FOOTER])
    }

    pub(super) fn trailer(&self) -> Vec<u8> { [&self.info[..], &self.footer[..]].concat() }

    pub(super) fn signer_info(&self, filename: &str) -> Result<Vec<u8>> { info(&self.info, filename) }

    pub(super) fn with_key_type(&self, key_type: u32) -> Result<Self> {
        if key_type > 1 { bail!("invalid ST2 key type {key_type}") }
        let mut footer = self.footer.clone(); footer[8..12].copy_from_slice(&key_type.to_le_bytes());
        Self::from_parts(&self.info, &footer)
    }

    pub(super) fn firmware_version(&self) -> Result<String> {
        let field = &self.info[32..48];
        let end = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
        let value = std::str::from_utf8(&field[..end]).context("CodeSigner firmware version is not UTF-8")?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') { bail!("invalid CodeSigner firmware version") }
        Ok(value.to_owned())
    }

    pub(super) fn rollback(&self) -> Result<u32> { le32(&self.footer, 0) }

    pub(super) fn sparse_seed(&self, block_size: usize) -> Result<Vec<u8>> {
        if block_size < 0x400 { bail!("sparse block is too small for CodeSigner data") }
        let mut block = vec![0; block_size];
        block[..FOOTER].copy_from_slice(&self.footer);
        block[0x300..0x400].copy_from_slice(&self.info);
        Ok(block)
    }
}

pub fn present(source: &Blob, boundary: u64) -> Result<bool> {
    if boundary < NORMAL as u64 || boundary > source.len()? { return Ok(false) }
    let mut marker = vec![0; MARKER.len()]; source.read_exact_at(boundary - NORMAL as u64, &mut marker)?; Ok(marker == MARKER)
}

fn le32(data: &[u8], at: usize) -> Result<u32> { Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated CodeSigner field")?.try_into().unwrap())) }
fn set32(data: &mut [u8], at: usize, value: u32) -> Result<()> { data.get_mut(at..at + 4).context("truncated CodeSigner field")?.copy_from_slice(&value.to_le_bytes()); Ok(()) }

fn info(template: &[u8], filename: &str) -> Result<Vec<u8>> {
    if template.len() != INFO || !template.starts_with(MARKER) { bail!("expected 0x100-byte SignerVer03 metadata") }
    let name = filename.as_bytes();
    if name.is_empty() || name.contains(&0) { bail!("invalid CodeSigner filename {filename:?}") }
    let mut out = template.to_vec();
    out[NAME..NAME + NAME_LEN].fill(0);
    let n = name.len().min(NAME_LEN - 1);
    out[NAME..NAME + n].copy_from_slice(&name[..n]);
    Ok(out)
}

fn key_index(key: &SigningKey) -> u32 { crc32fast::hash(&crypto::public_blob(key)) }

fn header(template: &[u8], key_type: u32, index: u32) -> Result<Vec<u8>> {
    if template.len() != FOOTER { bail!("ST2 ECDSA footer must be exactly 0x210 bytes") }
    let mut out = template.to_vec();
    set32(&mut out, 4, 4)?;
    set32(&mut out, 8, key_type)?;
    set32(&mut out, 12, index)?;
    out[HEADER..HEADER + SIGNATURE].fill(0);
    Ok(out)
}

pub fn extract(source: &Blob, boundary: u64) -> Result<Template> {
    if boundary > source.len()? || boundary < NORMAL as u64 { bail!("image is too small for CodeSigner v5") }
    let mut data = vec![0; NORMAL];
    source.read_exact_at(boundary - NORMAL as u64, &mut data)?;
    Template::from_trailer(&data).context("SignerVer03 trailer not found at the expected boundary")
}

pub fn append(payload: Blob, template: &Template, filename: &str, keys: &Keys) -> Result<Blob> {
    let key_type = template.key_type()?;
    let key = keys.st2(key_type)?;
    let info = info(&template.info, filename)?;
    let footer = header(&template.footer, key_type, key_index(key))?;
    let signed = blob::Concat::blob([payload.clone(), blob::bytes(info.clone()), blob::bytes(footer[..HEADER].to_vec())])?;
    let digest = blob::hash::<Sha512>(signed.as_ref(), signed.len()?)?;
    let signature = crypto::padded_signature(key, &digest)?;
    if !crypto::verify_padded(key.verifying_key(), &digest, &signature) { bail!("CodeSigner signature self-verification failed") }
    Ok(blob::Concat::blob([
        payload,
        blob::bytes(info),
        blob::bytes(footer[..HEADER].to_vec()),
        blob::bytes(signature.to_vec()),
        blob::bytes(footer[HEADER + SIGNATURE..].to_vec()),
    ])?)
}

pub fn append_vbmeta(payload: Vec<u8>, template: &Template, filename: &str, keys: &Keys) -> Result<Blob> {
    let size = (payload.len() as u64).checked_add(NORMAL as u64).context("vbmeta size overflow")?;
    if size > 1 << 20 { bail!("rebuilt {filename} is too large") }
    let image = append(blob::bytes(payload), template, filename, keys)?;
    if image.len()? != size { bail!("rebuilt {filename} changed size after CodeSigner") }
    Ok(image)
}

fn info_field(data: &[u8], start: usize, end: usize) -> Option<&[u8]> {
    let field = data.get(start..end)?;
    let len = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
    (len != 0 && field[len..].iter().all(|&byte| byte == 0)).then_some(&field[..len])
}

fn build_id(data: &[u8], start: usize, len: usize, optional: bool) -> bool {
    let Some(field) = data.get(start..start + 0x10) else { return false };
    if optional && field.iter().all(|&byte| byte == 0) { return true }
    info_field(data, start, start + 0x10).is_some_and(|value| {
        value.len() == len && value.last() == Some(&b'R')
            && value[..value.len() - 1].iter().all(u8::is_ascii_digit)
    })
}

fn matching_info(data: &[u8], expected: &[u8]) -> bool {
    let Some(id) = info_field(expected, 0x10, 0x20) else { return false };
    matches!(data.get(..12), Some(b"SignerVer01\0" | b"SignerVer02\0" | b"SignerVer03\0"))
        && data.get(0x0c..0x10) == expected.get(0x0c..0x10)
        && build_id(data, 0x10, id.len(), false)
        && info_field(data, 0x20, 0x30) == info_field(expected, 0x20, 0x30)
        && data.get(0x30..0x40) == expected.get(0x30..0x40)
        && info_field(data, 0x40, 0x50).is_some_and(|value| value.len() == 14 && value.iter().all(u8::is_ascii_digit))
        && data.get(0x50..NAME) == expected.get(0x50..NAME)
        && info_field(data, NAME, NAME + NAME_LEN) == info_field(expected, NAME, NAME + NAME_LEN)
        && build_id(data, 0xac, id.len(), true)
        && build_id(data, 0xbc, id.len(), true)
        && data.get(0xcc..INFO) == expected.get(0xcc..INFO)
}

pub fn ensure_signer_info(source: Blob, value: Vec<u8>) -> Result<Blob> {
    if value.len() != INFO || !value.starts_with(MARKER) { bail!("invalid logical SignerVer03 metadata") }
    if source.len()? < 0x400 { bail!("logical image is too small for SignerVer03 metadata") }
    let mut old = vec![0; INFO];
    source.read_exact_at(0x300, &mut old)?;
    if matching_info(&old, &value) { return Ok(source) }
    Ok(blob::patch(source, vec![(0x300, value)])?)
}

pub fn firmware_key_type(data: &[u8]) -> Option<u32> {
    if data.len() < FOOTER { return None }
    let footer = data.len() - FOOTER;
    let kind = le32(data, footer + 4).ok()?;
    let key_type = le32(data, footer + 8).ok()?;
    let key_index = le32(data, footer + 12).ok()?;
    let signature = data.get(data.len() - EXCLUDED..data.len() - EXCLUDED + SIGNATURE)?;
    if kind != 4 || key_type > 1 || key_index == 0 || signature[..20].iter().any(|&byte| byte != 0)
        || signature[68..88].iter().any(|&byte| byte != 0)
        || signature[20..68].iter().all(|&byte| byte == 0)
        || signature[88..136].iter().all(|&byte| byte == 0) {
        return None
    }
    Some(key_type)
}

pub fn sign_firmware(data: &mut [u8], keys: &Keys, description: &str) -> Result<u32> {
    if data.len() < FOOTER { bail!("ST2 firmware is too small: {description}") }
    let footer = data.len() - FOOTER;
    if le32(data, footer + 4)? != 4 { bail!("{description} is not CodeSigner type 4") }
    let key_type = le32(data, footer + 8)?;
    let key = keys.st2(key_type).with_context(|| format!("invalid key mode in {description}"))?;
    set32(data, footer + 12, key_index(key))?;
    let signature_at = data.len() - EXCLUDED;
    let digest = Sha512::digest(&data[..signature_at]);
    let signature = crypto::padded_signature(key, &digest)?;
    data[signature_at..signature_at + SIGNATURE].copy_from_slice(&signature);
    if !crypto::verify_padded(key.verifying_key(), &digest, &signature) { bail!("CodeSigner verification failed for {description}") }
    Ok(key_type)
}

pub fn verify_firmware(data: &[u8], keys: &Keys, description: &str) -> Result<u32> {
    let key_type = firmware_key_type(data).with_context(|| format!("no valid CodeSigner v5 footer in {description}"))?;
    let key = keys.st2(key_type)?;
    let footer = data.len() - FOOTER;
    if le32(data, footer + 12)? != key_index(key) { bail!("CodeSigner key index mismatch for {description}") }
    let signature_at = data.len() - EXCLUDED;
    let digest = Sha512::digest(&data[..signature_at]);
    if !crypto::verify_padded(key.verifying_key(), &digest, &data[signature_at..signature_at + SIGNATURE]) {
        bail!("CodeSigner signature does not match the selected {} key for {description}", if key_type == 0 { "TEE" } else { "REE" })
    }
    Ok(key_type)
}

pub fn sparse_template(source: &Blob) -> Result<Vec<u8>> {
    let mut block = vec![0; 4096]; source.read_exact_at(0, &mut block)?;
    let key_type = le32(&block, 8)?;
    if !block[0x300..0x400].starts_with(MARKER) || le32(&block, 4)? != 4 || key_type > 1 { bail!("Samsung sparse CodeSigner data is missing or uses an invalid key type") }
    Ok(block)
}

fn sparse_block(template: &[u8], filename: &str, key_type: u32, index: u32) -> Result<Vec<u8>> {
    if template.len() < 0x400 { bail!("sparse CodeSigner block is too small") }
    let mut out = template.to_vec();
    out[0x300..0x400].copy_from_slice(&info(&template[0x300..0x400], filename)?);
    set32(&mut out, 4, 4)?;
    set32(&mut out, 8, key_type)?;
    set32(&mut out, 12, index)?;
    out[0x10..0x10 + SIGNATURE].fill(0);
    Ok(out)
}

fn sparse_layout(source: Blob, signer: Vec<u8>) -> Result<Blob> {
    let mut header = [0u8; SPARSE_HEADER];
    source.read_exact_at(0, &mut header)?;
    if le32(&header, 0)? != 0xed26_ff3a || u16::from_le_bytes(header[4..6].try_into().unwrap()) != 1 || header[6..8] != [0, 0] || u16::from_le_bytes(header[8..10].try_into().unwrap()) as usize != SPARSE_HEADER || u16::from_le_bytes(header[10..12].try_into().unwrap()) as usize != CHUNK_HEADER || le32(&header, 24)? != 0 { bail!("unsupported Android sparse image") }
    let block = le32(&header, 12)? as usize;
    if signer.len() != block { bail!("stock/generated sparse block-size mismatch: {} != {block}", signer.len()) }
    let mut chunk = [0u8; CHUNK_HEADER];
    source.read_exact_at(SPARSE_HEADER as u64, &mut chunk)?;
    let kind = u16::from_le_bytes(chunk[..2].try_into().unwrap());
    let blocks = le32(&chunk, 4)?;
    let total = le32(&chunk, 8)?;
    if blocks == 0 { bail!("invalid first Android sparse chunk") }
    match kind {
        0xcac1 => {
            if total as u64 != CHUNK_HEADER as u64 + blocks as u64 * block as u64 { bail!("invalid first RAW sparse chunk") }
            blob::patch(source, vec![((SPARSE_HEADER + CHUNK_HEADER) as u64, signer)]).map_err(Into::into)
        }
        0xcac2 | 0xcac3 => {
            if total != CHUNK_HEADER as u32 + if kind == 0xcac2 { 4 } else { 0 } { bail!("invalid first FILL/DONT_CARE sparse chunk") }
            let mut updated_header = header.to_vec();
            if blocks > 1 { set32(&mut updated_header, 20, le32(&header, 20)?.checked_add(1).context("too many sparse chunks")?)? }
            let mut raw = Vec::with_capacity(CHUNK_HEADER);
            raw.extend_from_slice(&0xcac1u16.to_le_bytes()); raw.extend_from_slice(&0u16.to_le_bytes()); raw.extend_from_slice(&1u32.to_le_bytes()); raw.extend_from_slice(&(CHUNK_HEADER as u32 + block as u32).to_le_bytes());
            let first_end = (SPARSE_HEADER + CHUNK_HEADER) as u64 + if kind == 0xcac2 { 4 } else { 0 };
            let mut parts = vec![blob::bytes(updated_header), blob::bytes(raw), blob::bytes(signer)];
            if blocks > 1 {
                let mut rest = chunk.to_vec(); set32(&mut rest, 4, blocks - 1)?; parts.push(blob::bytes(rest));
                if kind == 0xcac2 { parts.push(blob::region(source.clone(), (SPARSE_HEADER + CHUNK_HEADER) as u64, 4)?); }
            }
            parts.push(blob::region(source.clone(), first_end, source.len()? - first_end)?);
            Ok(blob::Concat::blob(parts)?)
        }
        _ => bail!("unsupported first sparse chunk type {kind:#x}"),
    }
}

pub fn sign_sparse(source: Blob, template_block: &[u8], filename: &str, keys: &Keys) -> Result<Blob> {
    let key_type = le32(template_block, 8)?;
    let key = keys.st2(key_type)?;
    let unsigned = sparse_layout(source, sparse_block(template_block, filename, key_type, key_index(key))?)?;
    if unsigned.len()? < SPARSE_INFO { bail!("sparse image is too small for CodeSigner") }
    let payload = blob::hash_range::<Sha512>(unsigned.as_ref(), SPARSE_INFO, unsigned.len()? - SPARSE_INFO)?;
    let mut header = [0; HEADER];
    unsigned.read_exact_at(0x28, &mut header)?;
    let digest = Sha512::digest([payload.as_slice(), &header].concat());
    let signature = crypto::padded_signature(key, &digest)?;
    if !crypto::verify_padded(key.verifying_key(), &digest, &signature) { bail!("sparse CodeSigner signature self-verification failed") }
    Ok(blob::patch(unsigned, vec![(SPARSE_SIGNATURE, signature.to_vec())])?)
}
