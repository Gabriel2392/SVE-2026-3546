use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2_10::{Digest, Sha256};

use crate::io::ReadAt;
use super::{blob::{self, Blob}, crypto::Keys};

const HEADER: usize = 256;
const FOOTER: usize = 64;
const BLOCK: u64 = 4096;

fn be32(data: &[u8], at: usize) -> Result<u32> { Ok(u32::from_be_bytes(data.get(at..at + 4).context("truncated AVB u32")?.try_into().unwrap())) }
fn be64(data: &[u8], at: usize) -> Result<u64> { Ok(u64::from_be_bytes(data.get(at..at + 8).context("truncated AVB u64")?.try_into().unwrap())) }
fn set32(data: &mut [u8], at: usize, value: u32) { data[at..at + 4].copy_from_slice(&value.to_be_bytes()) }
fn set64(data: &mut [u8], at: usize, value: u64) { data[at..at + 8].copy_from_slice(&value.to_be_bytes()) }
fn round(value: u64, multiple: u64) -> Result<u64> { value.checked_add(multiple - 1).map(|value| value / multiple * multiple).context("AVB size overflow") }

#[derive(Clone, Debug)]
pub struct Footer { version_major: u32, version_minor: u32, pub original_size: u64, pub vbmeta_offset: u64, pub vbmeta_size: u64 }

impl Footer {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != FOOTER || &data[..4] != b"AVBf" { bail!("invalid AVB footer") }
        Ok(Self { version_major: be32(data, 4)?, version_minor: be32(data, 8)?, original_size: be64(data, 12)?, vbmeta_offset: be64(data, 20)?, vbmeta_size: be64(data, 28)? })
    }

    fn encode(&self) -> Vec<u8> {
        let mut data = vec![0; FOOTER];
        data[..4].copy_from_slice(b"AVBf"); set32(&mut data, 4, self.version_major); set32(&mut data, 8, self.version_minor);
        set64(&mut data, 12, self.original_size); set64(&mut data, 20, self.vbmeta_offset); set64(&mut data, 28, self.vbmeta_size);
        data
    }
}

pub fn payload_boundary(source: &Blob, boundary: u64) -> Result<Option<u64>> {
    if boundary < FOOTER as u64 || boundary > source.len()? { return Ok(None) }
    let mut data = [0; FOOTER]; source.read_exact_at(boundary - FOOTER as u64, &mut data)?;
    if &data[..4] != b"AVBf" { return Ok(None) }
    let footer = Footer::parse(&data)?;
    if footer.original_size == 0 || footer.original_size > footer.vbmeta_offset || footer.vbmeta_offset.checked_add(footer.vbmeta_size).is_none_or(|end| end > boundary - FOOTER as u64) { bail!("invalid AVB wrapper boundaries") }
    Ok(Some(footer.original_size))
}

#[derive(Clone, Debug)]
pub struct Header {
    pub required_minor: u32,
    pub auth_size: u64,
    pub aux_size: u64,
    pub algorithm: u32,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub descriptors_offset: u64,
    pub descriptors_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_location: u32,
    release: [u8; 48],
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != HEADER || &data[..4] != b"AVB0" || be32(data, 4)? != 1 { bail!("unsupported AVB header") }
        let header = Self {
            required_minor: be32(data, 8)?, auth_size: be64(data, 12)?, aux_size: be64(data, 20)?, algorithm: be32(data, 28)?,
            public_key_offset: be64(data, 64)?, public_key_size: be64(data, 72)?, descriptors_offset: be64(data, 96)?,
            descriptors_size: be64(data, 104)?, rollback_index: be64(data, 112)?, flags: be32(data, 120)?, rollback_location: be32(data, 124)?,
            release: data[128..176].try_into().unwrap(),
        };
        let signing = match header.algorithm {
            0 => header.auth_size == 0 && header.public_key_size == 0 && (32..64).step_by(8).all(|at| be64(data, at).is_ok_and(|value| value == 0)),
            2 => header.auth_size == 576 && header.public_key_size == 1032 && be64(data, 32)? == 0 && be64(data, 40)? == 32
                && be64(data, 48)? == 32 && be64(data, 56)? == 512,
            _ => false,
        };
        if !signing || header.aux_size % 64 != 0 || header.descriptors_offset.checked_add(header.descriptors_size).is_none_or(|end| end > header.aux_size)
            || header.public_key_offset.checked_add(header.public_key_size).is_none_or(|end| end > header.aux_size) {
            bail!("unsupported or invalid AVB block layout")
        }
        Ok(header)
    }

    fn signed(template: &Self, descriptors: u64, key: u64, aux: u64, minor: u32) -> Result<Vec<u8>> {
        let mut data = vec![0; HEADER];
        data[..4].copy_from_slice(b"AVB0"); set32(&mut data, 4, 1); set32(&mut data, 8, minor);
        set64(&mut data, 12, 576); set64(&mut data, 20, aux); set32(&mut data, 28, 2);
        set64(&mut data, 32, 0); set64(&mut data, 40, 32); set64(&mut data, 48, 32); set64(&mut data, 56, 512);
        set64(&mut data, 64, descriptors); set64(&mut data, 72, key); set64(&mut data, 80, descriptors + key); set64(&mut data, 88, 0);
        set64(&mut data, 96, 0); set64(&mut data, 104, descriptors); set64(&mut data, 112, template.rollback_index);
        set32(&mut data, 120, template.flags); set32(&mut data, 124, template.rollback_location); data[128..176].copy_from_slice(&template.release);
        Ok(data)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor(Vec<u8>);

#[derive(Clone, Debug)]
pub struct HashParameters { pub image_size: u64, pub algorithm: String, pub name: String, pub salt: Vec<u8>, pub digest: Vec<u8>, pub flags: u32 }

#[derive(Clone, Debug)]
pub struct TreeParameters {
    pub image_size: u64, pub tree_offset: u64, pub tree_size: u64, pub data_block: u32, pub hash_block: u32,
    pub fec_roots: u32, pub fec_offset: u64, pub fec_size: u64, pub algorithm: String, pub name: String,
    pub salt: Vec<u8>, pub root: Vec<u8>, pub flags: u32,
}

fn text(data: &[u8]) -> Result<String> {
    let end = data.iter().position(|&byte| byte == 0).unwrap_or(data.len());
    Ok(std::str::from_utf8(&data[..end]).context("AVB string is not UTF-8")?.to_owned())
}

impl Descriptor {
    pub fn tag(&self) -> u64 { u64::from_be_bytes(self.0[..8].try_into().unwrap()) }

    pub fn name(&self) -> Result<Option<String>> {
        let (fixed, at) = match self.tag() { 1 => (180, 104), 2 => (132, 56), 4 => (92, 20), _ => return Ok(None) };
        let len = be32(&self.0, at)? as usize;
        Ok(Some(std::str::from_utf8(self.0.get(fixed..fixed + len).context("truncated AVB partition name")?).context("AVB partition name is not UTF-8")?.to_owned()))
    }

    pub fn hash(&self) -> Result<Option<HashParameters>> {
        if self.tag() != 2 { return Ok(None) }
        if self.0.len() < 132 { bail!("truncated AVB hash descriptor") }
        let name_len = be32(&self.0, 56)? as usize;
        let salt_len = be32(&self.0, 60)? as usize;
        let digest_len = be32(&self.0, 64)? as usize;
        let variable = self.0.get(132..132 + name_len + salt_len + digest_len).context("truncated AVB hash descriptor data")?;
        Ok(Some(HashParameters {
            image_size: be64(&self.0, 16)?, algorithm: text(&self.0[24..56])?, name: std::str::from_utf8(&variable[..name_len])?.into(),
            salt: variable[name_len..name_len + salt_len].to_vec(), digest: variable[name_len + salt_len..].to_vec(), flags: be32(&self.0, 68)?,
        }))
    }

    pub fn tree(&self) -> Result<Option<TreeParameters>> {
        if self.tag() != 1 { return Ok(None) }
        if self.0.len() < 180 { bail!("truncated AVB hashtree descriptor") }
        let name_len = be32(&self.0, 104)? as usize;
        let salt_len = be32(&self.0, 108)? as usize;
        let root_len = be32(&self.0, 112)? as usize;
        let variable = self.0.get(180..180 + name_len + salt_len + root_len).context("truncated AVB hashtree descriptor data")?;
        Ok(Some(TreeParameters {
            image_size: be64(&self.0, 20)?, tree_offset: be64(&self.0, 28)?, tree_size: be64(&self.0, 36)?, data_block: be32(&self.0, 44)?, hash_block: be32(&self.0, 48)?,
            fec_roots: be32(&self.0, 52)?, fec_offset: be64(&self.0, 56)?, fec_size: be64(&self.0, 64)?, algorithm: text(&self.0[72..104])?,
            name: std::str::from_utf8(&variable[..name_len])?.into(), salt: variable[name_len..name_len + salt_len].to_vec(), root: variable[name_len + salt_len..].to_vec(), flags: be32(&self.0, 116)?,
        }))
    }

    fn replace_chain_key(&mut self, key: &[u8]) -> Result<()> {
        if self.tag() != 4 { return Ok(()) }
        let name = be32(&self.0, 20)? as usize;
        let size = be32(&self.0, 24)? as usize;
        if size != key.len() { bail!("AVB chain key size changed: {size} != {}", key.len()) }
        self.0.get_mut(92 + name..92 + name + size).context("truncated AVB chain key")?.copy_from_slice(key);
        Ok(())
    }

    fn updated_hash(&self, size: u64, digest: &[u8]) -> Result<Self> {
        let parameters = self.hash()?.context("descriptor is not a hash descriptor")?;
        if digest.len() != parameters.digest.len() { bail!("AVB hash digest size changed") }
        let mut out = self.clone(); set64(&mut out.0, 16, size);
        let at = 132 + parameters.name.len() + parameters.salt.len(); out.0[at..at + digest.len()].copy_from_slice(digest);
        Ok(out)
    }

    fn updated_tree(&self, size: u64, tree_size: u64, fec_roots: u32, fec_size: u64, root: &[u8]) -> Result<Self> {
        let parameters = self.tree()?.context("descriptor is not a hashtree descriptor")?;
        if root.len() != parameters.root.len() { bail!("AVB root digest size changed") }
        let mut out = self.clone(); set64(&mut out.0, 20, size); set64(&mut out.0, 28, size); set64(&mut out.0, 36, tree_size);
        let fec_offset = size.checked_add(tree_size).context("AVB FEC offset overflow")?;
        set32(&mut out.0, 52, fec_roots); set64(&mut out.0, 56, if fec_roots == 0 { 0 } else { fec_offset }); set64(&mut out.0, 64, fec_size);
        let at = 180 + parameters.name.len() + parameters.salt.len(); out.0[at..at + root.len()].copy_from_slice(root);
        Ok(out)
    }
}

fn descriptors(data: &[u8]) -> Result<Vec<Descriptor>> {
    let mut at = 0;
    let mut out = Vec::new();
    while at < data.len() {
        if data.len() - at < 16 { bail!("truncated AVB descriptor") }
        let size = usize::try_from(be64(data, at + 8)?).context("AVB descriptor too large")?;
        let end = at.checked_add(16).and_then(|at| at.checked_add(size)).filter(|&end| end <= data.len()).context("AVB descriptor exceeds block")?;
        out.push(Descriptor(data[at..end].to_vec())); at = end;
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IntegrityKind { Hash, Hashtree }

#[derive(Clone, Debug)]
pub(super) struct GenerationPolicy {
    pub data_block: u32,
    pub hash_block: u32,
    pub fec_roots: u32,
    pub flags: u32,
    pub rollback_index: u64,
    pub rollback_location: u32,
    pub footer_version_major: u32,
    pub footer_version_minor: u32,
    pub release: String,
}

pub(super) fn minimum_capacity(kind: IntegrityKind, payload: u64, policy: &GenerationPolicy) -> Result<u64> {
    if payload == 0 || policy.data_block < 512 || policy.data_block != policy.hash_block || !policy.data_block.is_power_of_two() || policy.fec_roots >= 255 {
        bail!("invalid generated AVB capacity policy")
    }
    let block = policy.data_block as u64;
    let aligned = round(payload, block)?;
    let integrity = match kind {
        IntegrityKind::Hash => 0,
        IntegrityKind::Hashtree => {
            let mut value = aligned;
            let mut tree = 0u64;
            while value > block {
                let level = round(value.div_ceil(block).checked_mul(32).context("AVB tree size overflow")?, block)?;
                tree = tree.checked_add(level).context("AVB tree size overflow")?;
                value = level;
            }
            let fec = if policy.fec_roots == 0 { 0 } else {
                let covered = aligned.checked_add(tree).context("AVB FEC size overflow")?;
                let rsn = 255u64 - policy.fec_roots as u64;
                covered.div_ceil(block).div_ceil(rsn).checked_mul(policy.fec_roots as u64).and_then(|value| value.checked_mul(block)).context("AVB FEC size overflow")?
            };
            tree.checked_add(fec).context("AVB integrity size overflow")?
        }
    };
    round(aligned.checked_add(integrity).and_then(|value| value.checked_add(BLOCK * 2)).context("AVB capacity overflow")?, BLOCK)
}

fn descriptor_block(tag: u64, fixed: usize, variable: &[u8]) -> Vec<u8> {
    let total = (fixed + variable.len()).next_multiple_of(8);
    let mut out = vec![0; total];
    out[..8].copy_from_slice(&tag.to_be_bytes());
    out[8..16].copy_from_slice(&((total - 16) as u64).to_be_bytes());
    out[fixed..fixed + variable.len()].copy_from_slice(variable);
    out
}

pub(super) fn generated_template(kind: IntegrityKind, name: &str, capacity: u64,
                                 payload_size: u64, salt: &[u8], policy: &GenerationPolicy) -> Result<Parsed> {
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) {
        bail!("invalid generated AVB partition name {name:?}")
    }
    if salt.len() != 32 { bail!("generated AVB salt must be SHA-256 sized") }
    if capacity < BLOCK * 4 || capacity % BLOCK != 0 || payload_size == 0 || payload_size >= capacity {
        bail!("invalid generated AVB partition capacity")
    }
    if policy.data_block < 512 || !policy.data_block.is_power_of_two()
        || policy.hash_block < 512 || !policy.hash_block.is_power_of_two()
        || policy.fec_roots >= 255 || policy.release.len() > 47 || !policy.release.is_ascii() {
        bail!("invalid generated AVB policy")
    }
    let mut variable = Vec::with_capacity(name.len() + salt.len() + 32);
    variable.extend_from_slice(name.as_bytes()); variable.extend_from_slice(salt); variable.extend_from_slice(&[0; 32]);
    let descriptor = match kind {
        IntegrityKind::Hash => {
            if policy.flags & !1 != 0 { bail!("unsupported generated AVB hash flags") }
            let mut value = descriptor_block(2, 132, &variable);
            set64(&mut value, 16, payload_size); value[24..30].copy_from_slice(b"sha256");
            set32(&mut value, 56, name.len() as u32); set32(&mut value, 60, salt.len() as u32); set32(&mut value, 64, 32); set32(&mut value, 68, policy.flags);
            Descriptor(value)
        }
        IntegrityKind::Hashtree => {
            if policy.flags & !3 != 0 || policy.data_block != policy.hash_block { bail!("unsupported generated AVB hashtree policy") }
            let aligned = round(payload_size, policy.data_block as u64)?;
            let mut value = descriptor_block(1, 180, &variable);
            set32(&mut value, 16, 1); set64(&mut value, 20, payload_size); set64(&mut value, 28, aligned); set64(&mut value, 36, policy.hash_block as u64);
            set32(&mut value, 44, policy.data_block); set32(&mut value, 48, policy.hash_block); set32(&mut value, 52, policy.fec_roots);
            set64(&mut value, 56, if policy.fec_roots == 0 { 0 } else { aligned + policy.hash_block as u64 });
            set64(&mut value, 64, if policy.fec_roots == 0 { 0 } else { policy.data_block as u64 }); value[72..78].copy_from_slice(b"sha256");
            set32(&mut value, 104, name.len() as u32); set32(&mut value, 108, salt.len() as u32); set32(&mut value, 112, 32); set32(&mut value, 116, policy.flags);
            Descriptor(value)
        }
    };
    let mut release = [0; 48]; release[..policy.release.len()].copy_from_slice(policy.release.as_bytes());
    let header = Header {
        required_minor: if policy.flags == 0 { 0 } else { 1 }, auth_size: 576, aux_size: 0, algorithm: 2,
        public_key_offset: 0, public_key_size: 1032, descriptors_offset: 0,
        descriptors_size: descriptor.0.len() as u64, rollback_index: policy.rollback_index,
        flags: 0, rollback_location: policy.rollback_location, release,
    };
    Ok(Parsed {
        source: blob::zeroes(capacity),
        footer: Some(Footer { version_major: policy.footer_version_major, version_minor: policy.footer_version_minor, original_size: payload_size, vbmeta_offset: 0, vbmeta_size: 0 }),
        header, descriptors: vec![descriptor], image_size: capacity, block_size: BLOCK,
    })
}

#[derive(Clone)]
pub struct Parsed {
    pub source: Blob,
    pub footer: Option<Footer>,
    pub header: Header,
    pub descriptors: Vec<Descriptor>,
    pub image_size: u64,
    pub block_size: u64,
}

pub fn parse(source: Blob) -> Result<Parsed> {
    let image_size = source.len()?;
    if image_size < FOOTER as u64 { bail!("image is too small for AVB") }
    let mut tail = [0; FOOTER]; source.read_exact_at(image_size - FOOTER as u64, &mut tail)?;
    let footer = (&tail[..4] == b"AVBf").then(|| Footer::parse(&tail)).transpose()?;
    let vbmeta = footer.as_ref().map_or(0, |footer| footer.vbmeta_offset);
    if let Some(footer) = &footer {
        if footer.original_size == 0 || footer.original_size > footer.vbmeta_offset || footer.vbmeta_offset.checked_add(footer.vbmeta_size).is_none_or(|end| end > image_size - FOOTER as u64) { bail!("invalid AVB footer boundaries") }
    }
    let mut encoded = [0; HEADER]; source.read_exact_at(vbmeta, &mut encoded)?;
    let header = Header::parse(&encoded)?;
    let total = HEADER as u64 + header.auth_size + header.aux_size;
    if vbmeta.checked_add(total).is_none_or(|end| end > image_size) { bail!("truncated AVB metadata") }
    let start = vbmeta + HEADER as u64 + header.auth_size + header.descriptors_offset;
    let mut raw = vec![0; usize::try_from(header.descriptors_size).context("AVB descriptors too large")?]; source.read_exact_at(start, &mut raw)?;
    Ok(Parsed { source, footer, header, descriptors: descriptors(&raw)?, image_size, block_size: BLOCK })
}

fn generate(list: &[Descriptor], template: &Header, keys: &Keys, minor: u32) -> Result<Vec<u8>> {
    if keys.avb_public.len() != 1032 { bail!("AVB public key is not RSA-4096") }
    let encoded = list.iter().flat_map(|descriptor| descriptor.0.iter().copied()).collect::<Vec<_>>();
    let unpadded = encoded.len().checked_add(keys.avb_public.len()).context("AVB auxiliary size overflow")?;
    let aux_size = round(unpadded as u64, 64)?;
    let header = Header::signed(template, encoded.len() as u64, keys.avb_public.len() as u64, aux_size, minor)?;
    let mut aux = Vec::with_capacity(aux_size as usize); aux.extend_from_slice(&encoded); aux.extend_from_slice(&keys.avb_public); aux.resize(aux_size as usize, 0);
    let mut hasher = Sha256::new(); hasher.update(&header); hasher.update(&aux); let digest = hasher.finalize();
    let signature = keys.avb.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).context("AVB RSA signing failed")?;
    if signature.len() != 512 { bail!("AVB RSA signature has wrong size") }
    RsaPublicKey::from(&keys.avb).verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .context("AVB RSA signature self-verification failed")?;
    let mut auth = Vec::with_capacity(576); auth.extend_from_slice(&digest); auth.extend_from_slice(&signature); auth.resize(576, 0);
    Ok([header, auth, aux].concat())
}

fn replace_chain_keys(list: &mut [Descriptor], key: &[u8]) -> Result<()> { for descriptor in list { descriptor.replace_chain_key(key)? } Ok(()) }

fn integrity(list: &[Descriptor]) -> Result<(usize, Descriptor)> {
    let found = list.iter().enumerate().filter(|(_, descriptor)| matches!(descriptor.tag(), 1 | 2)).collect::<Vec<_>>();
    if found.len() != 1 { bail!("expected exactly one AVB integrity descriptor, got {}", found.len()) }
    Ok((found[0].0, found[0].1.clone()))
}

fn footer_block(footer: &Footer, block: u64) -> Result<Blob> {
    let padding = block.checked_sub(FOOTER as u64).context("AVB block is too small")?;
    blob::Concat::blob([blob::zeroes(padding), blob::bytes(footer.encode())]).map_err(Into::into)
}

pub fn resign_metadata(parsed: &Parsed, keys: &Keys) -> Result<(Blob, Descriptor)> {
    let footer = parsed.footer.as_ref().context("logical partition has no AVB footer")?;
    let mut list = parsed.descriptors.clone(); replace_chain_keys(&mut list, &keys.avb_public)?;
    let blob = generate(&list, &parsed.header, keys, parsed.header.required_minor)?;
    let blob_size = blob.len() as u64;
    let footer_at = parsed.image_size.checked_sub(parsed.block_size).context("AVB partition is too short")?;
    if footer.vbmeta_offset + blob.len() as u64 > footer_at { bail!("new AVB metadata does not fit partition") }
    let old_end = (footer.vbmeta_offset + round(footer.vbmeta_size, parsed.block_size)?).min(footer_at);
    let mut replacement = blob; replacement.resize((old_end - footer.vbmeta_offset) as usize, 0);
    let mut updated = footer.clone(); updated.vbmeta_size = blob_size;
    let source = blob::patch(parsed.source.clone(), vec![(footer.vbmeta_offset, replacement), (footer_at, read_blob(&footer_block(&updated, parsed.block_size)?)?)])?;
    Ok((source, integrity(&list)?.1))
}

fn read_blob(source: &Blob) -> Result<Vec<u8>> { Ok(blob::read_all(source.as_ref(), 1 << 20)?) }

fn with_extras(template: &Parsed, replacement: Descriptor, keys: &Keys) -> Result<Vec<Descriptor>> {
    let (integrity_at, _) = integrity(&template.descriptors)?;
    let mut unnamed = Vec::new();
    let mut named = BTreeMap::new();
    for (index, mut descriptor) in template.descriptors.iter().cloned().enumerate() {
        if index == integrity_at { continue }
        descriptor.replace_chain_key(&keys.avb_public)?;
        if let Some(name) = descriptor.name()? {
            let class = match descriptor.tag() { 1 => "AvbHashtreeDescriptor", 2 => "AvbHashDescriptor", 4 => "AvbChainPartitionDescriptor", _ => "AvbDescriptor" };
            named.insert(format!("{class}_{name}"), descriptor);
        } else { unnamed.push(descriptor) }
    }
    let mut out = vec![replacement]; out.extend(unnamed); out.extend(named.into_values()); Ok(out)
}

fn hash_with_salt(source: &dyn ReadAt, size: u64, salt: &[u8]) -> Result<Vec<u8>> {
    let mut hash = Sha256::new(); hash.update(salt);
    let mut buffer = vec![0; 1 << 20]; let mut at = 0;
    while at < size { let count = buffer.len().min((size - at) as usize); source.read_exact_at(at, &mut buffer[..count])?; hash.update(&buffer[..count]); at += count as u64; }
    Ok(hash.finalize().to_vec())
}

fn wrap(payload: Blob, original: u64, descriptor: Descriptor, template: &Parsed, keys: &Keys, integrity: Vec<Vec<u8>>) -> Result<(Blob, Descriptor)> {
    let payload_size = payload.len()?;
    if original > payload_size { bail!("AVB original image size exceeds payload") }
    let mut parts = vec![payload];
    let aligned = round(payload_size, template.block_size)?;
    if aligned > payload_size { parts.push(blob::zeroes(aligned - payload_size)) }
    parts.extend(integrity.into_iter().map(blob::bytes));
    let vbmeta_at = parts.iter().try_fold(0u64, |size, part| Ok::<_, anyhow::Error>(size.checked_add(part.len()?).context("AVB image size overflow")?))?;
    let list = with_extras(template, descriptor.clone(), keys)?;
    let minor = template.header.required_minor.max(if descriptor.hash()?.is_some_and(|hash| hash.flags != 0) || descriptor.tree()?.is_some_and(|tree| tree.flags != 0) { 1 } else { 0 });
    let vbmeta = generate(&list, &template.header, keys, minor)?;
    let padded = round(vbmeta.len() as u64, template.block_size)?;
    parts.push(blob::bytes(vbmeta.clone())); if padded > vbmeta.len() as u64 { parts.push(blob::zeroes(padded - vbmeta.len() as u64)) }
    let footer_at = template.image_size.checked_sub(template.block_size).context("AVB partition is too short")?;
    let used = vbmeta_at + padded;
    if used > footer_at { bail!("signed AVB image does not fit stock partition") }
    parts.push(blob::zeroes(footer_at - used));
    let stock = template.footer.as_ref().context("stock AVB footer is missing")?;
    let footer = Footer { version_major: stock.version_major, version_minor: stock.version_minor, original_size: original, vbmeta_offset: vbmeta_at, vbmeta_size: vbmeta.len() as u64 };
    parts.push(footer_block(&footer, template.block_size)?);
    Ok((blob::Concat::blob(parts)?, descriptor))
}

pub fn add_hash_footer(payload: Blob, template: &Parsed, keys: &Keys) -> Result<(Blob, Descriptor)> {
    let (_, descriptor) = integrity(&template.descriptors)?;
    let parameters = descriptor.hash()?.context("stock AVB descriptor is not a hash descriptor")?;
    if parameters.algorithm != "sha256" || parameters.flags & !1 != 0 { bail!("unsupported AVB hash parameters") }
    let size = payload.len()?;
    let digest = if parameters.digest.is_empty() { Vec::new() } else { hash_with_salt(payload.as_ref(), size, &parameters.salt)? };
    let updated = descriptor.updated_hash(size, &digest)?;
    wrap(payload, size, updated, template, keys, vec![])
}

fn hash_tree(source: &dyn ReadAt, size: u64, block: u64, salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if block == 0 || !block.is_power_of_two() || size == 0 || size % block != 0 { bail!("invalid AVB hashtree geometry") }
    let digest_slot = 32u64;
    let mut level_sizes = Vec::new(); let mut value = size;
    while value > block { let blocks = value.div_ceil(block); let level = round(blocks * digest_slot, block)?; level_sizes.push(level); value = level; }
    if level_sizes.is_empty() { return Ok((hash_with_salt(source, block, salt)?, Vec::new())) }
    let tree_size: u64 = level_sizes.iter().sum();
    let mut offsets = Vec::with_capacity(level_sizes.len());
    for index in 0..level_sizes.len() { offsets.push(level_sizes[index + 1..].iter().sum::<u64>()); }
    let mut tree = vec![0; usize::try_from(tree_size).context("AVB hashtree exceeds memory")?];
    let mut input_size = size; let mut buffer = vec![0; block as usize]; let mut last = Vec::new();
    for level in 0..level_sizes.len() {
        let mut output = Vec::with_capacity(level_sizes[level] as usize);
        let mut at = 0;
        while at < input_size {
            let count = block.min(input_size - at) as usize; buffer.fill(0);
            if level == 0 { source.read_exact_at(at, &mut buffer[..count])? } else { let start = offsets[level - 1] + at; buffer[..count].copy_from_slice(&tree[start as usize..start as usize + count]); }
            let mut hash = Sha256::new(); hash.update(salt); hash.update(&buffer); output.extend_from_slice(&hash.finalize()); at += count as u64;
        }
        output.resize(level_sizes[level] as usize, 0); let target = offsets[level] as usize; tree[target..target + output.len()].copy_from_slice(&output); last = output; input_size = level_sizes[level];
    }
    let mut root = Sha256::new(); root.update(salt); root.update(&last); Ok((root.finalize().to_vec(), tree))
}

fn fec(source: &dyn ReadAt, size: u64, block: u64, roots: usize) -> Result<Vec<u8>> {
    if block != 4096 || roots == 0 || roots >= 255 || size % block != 0 { bail!("invalid AVB FEC geometry") }
    let rsn = 255 - roots;
    let blocks = size / block;
    let rounds = blocks.div_ceil(rsn as u64);
    let output_size = rounds.checked_mul(roots as u64).and_then(|value| value.checked_mul(block)).context("AVB FEC size overflow")?;
    let code = super::fec::ReedSolomon::new(roots);
    let mut input = vec![0; block as usize];
    let mut output = vec![0; usize::try_from(output_size).context("AVB FEC exceeds memory")?];
    for column in 0..rsn as u64 {
        crate::cancel::check()?;
        for round in 0..rounds {
            let index = column * rounds + round;
            if index < blocks { source.read_exact_at(index * block, &mut input)? } else { input.fill(0) }
            let at = round as usize * roots * block as usize;
            for (row, &byte) in input.iter().enumerate() {
                code.update(byte, &mut output[at + row * roots..at + (row + 1) * roots]);
            }
        }
    }
    Ok(output)
}

pub fn add_hashtree_footer(payload: Blob, template: &Parsed, keys: &Keys) -> Result<(Blob, Descriptor)> {
    let (_, descriptor) = integrity(&template.descriptors)?;
    let parameters = descriptor.tree()?.context("stock AVB descriptor is not a hashtree descriptor")?;
    let stock_tree = round(parameters.image_size, parameters.data_block as u64)?;
    let stock_fec = parameters.tree_offset.checked_add(parameters.tree_size).context("stock AVB FEC offset overflow")?;
    if parameters.algorithm != "sha256" || parameters.data_block != parameters.hash_block || parameters.fec_roots >= 255 || parameters.flags & !3 != 0
        || parameters.tree_offset != stock_tree || parameters.tree_size % parameters.hash_block as u64 != 0
        || (parameters.fec_roots == 0 && (parameters.fec_offset != 0 || parameters.fec_size != 0))
        || (parameters.fec_roots != 0 && (parameters.fec_offset != stock_fec || parameters.fec_size % parameters.data_block as u64 != 0)) {
        bail!("unsupported or inconsistent AVB hashtree parameters")
    }
    let original = payload.len()?; let size = round(original, parameters.data_block as u64)?;
    let padded = if size == original { payload } else { blob::Concat::blob([payload, blob::zeroes(size - original)])? };
    let (root, tree) = hash_tree(padded.as_ref(), size, parameters.data_block as u64, &parameters.salt)?;
    let fec = if parameters.fec_roots == 0 { vec![] } else {
        let covered = blob::Concat::blob([padded.clone(), blob::bytes(tree.clone())])?;
        fec(covered.as_ref(), covered.len()?, parameters.data_block as u64, parameters.fec_roots as usize)?
    };
    let root = if parameters.root.is_empty() { Vec::new() } else { root };
    let updated = descriptor.updated_tree(size, tree.len() as u64, parameters.fec_roots, fec.len() as u64, &root)?;
    wrap(padded, original, updated, template, keys, vec![tree, fec])
}

pub fn add_footer(payload: Blob, template: &Parsed, keys: &Keys) -> Result<(Blob, Descriptor)> {
    let (_, descriptor) = integrity(&template.descriptors)?;
    match descriptor.tag() { 1 => add_hashtree_footer(payload, template, keys), 2 => add_hash_footer(payload, template, keys), tag => bail!("unsupported AVB integrity descriptor {tag}") }
}

pub fn standalone(template: &Parsed, replacements: &BTreeMap<String, Descriptor>, targets: &std::collections::BTreeSet<String>,
                  managed: &std::collections::BTreeSet<String>, keys: &Keys) -> Result<Vec<u8>> {
    if template.footer.is_some() { bail!("standalone vbmeta unexpectedly has an AVB footer") }
    let mut list = Vec::with_capacity(template.descriptors.len() + replacements.len());
    let mut seen = std::collections::BTreeSet::new();
    for mut descriptor in template.descriptors.clone() {
        if matches!(descriptor.tag(), 1 | 2) {
            let name = descriptor.name()?.context("vbmeta integrity descriptor has no partition name")?;
            if managed.contains(&name) && !targets.contains(&name) { continue }
            if let Some(replacement) = replacements.get(&name) {
                if replacement.tag() != descriptor.tag() { bail!("AVB descriptor type changed for {name}") }
                descriptor = replacement.clone();
            } else if targets.contains(&name) {
                bail!("no freshly signed descriptor for configured Android partition {name}")
            }
            if targets.contains(&name) { seen.insert(name); }
        } else if descriptor.tag() == 4 {
            let name = descriptor.name()?.context("AVB chain descriptor has no partition name")?;
            if managed.contains(&name) && !targets.contains(&name) { continue }
            if targets.contains(&name) { descriptor.replace_chain_key(&keys.avb_public)?; seen.insert(name); }
        }
        list.push(descriptor);
    }
    for (name, descriptor) in replacements {
        if targets.contains(name) && !seen.contains(name) { list.push(descriptor.clone()); }
    }
    generate(&list, &template.header, keys, template.header.required_minor)
}
