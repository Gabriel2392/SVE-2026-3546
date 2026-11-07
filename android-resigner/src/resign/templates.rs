use std::{collections::{BTreeMap, BTreeSet}, fs::File, io::Read, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use p384::{EncodedPoint, ecdsa::VerifyingKey};
use sha2_10::{Digest, Sha512};

use crate::{archive::TarIndex, io::ReadAt};
use super::{avb, blob::{self, Blob}, codesigner::Template, crypto};

const LZ4_MAGIC: [u8; 4] = 0x184d_2204u32.to_le_bytes();
const MAX_MEMBER: u64 = 128 << 20;
const MARKER: &[u8] = b"SignerVer03";
const TRAILER: usize = 0x310;
const SLSI: &[u8] = b"SLSI";
const P384: usize = 524;

#[derive(Clone)]
pub(super) struct Catalog {
    version: String,
    templates: BTreeMap<u32, Template>,
    vbmeta: Option<Vec<u8>>,
    firmware_key: Option<Vec<u8>>,
}

struct Keystorage { firmware_key: Option<Vec<u8>> }

fn le32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(data.get(at..at + 4).context("truncated keystorage field")?.try_into().unwrap()))
}

fn keystorage(data: &[u8]) -> Result<Option<Keystorage>> {
    if data.get(..4) != Some(SLSI) { return Ok(None) }
    let version = le32(data, 4)?;
    if !matches!(version, 0x40 | 0x50) { return Ok(None) }
    let header = le32(data, 8)? as usize;
    let count = le32(data, 12)? as usize;
    let body = le32(data, 0x20)? as usize;
    let record = if version == 0x50 { 2592 } else { 1056 };
    let meta = 48 + if version == 0x50 { 24 * 16 } else { 12 * 16 };
    let meta_len = 24;
    let slots = header.checked_sub(meta).filter(|value| value % meta_len == 0)
        .map(|value| value / meta_len).context("invalid keystorage metadata")?;
    header.checked_add(body).filter(|&end| end <= data.len()).context("invalid keystorage body")?;
    if count == 0 || count > slots || body != count.checked_mul(record).context("keystorage size overflow")? {
        bail!("invalid keystorage table")
    }
    let mut names = BTreeSet::new();
    let mut indexes = BTreeSet::new();
    let mut found = None;
    for slot in 0..count {
        let item = meta + slot * meta_len;
        let raw = data.get(item..item + 16).context("truncated keystorage metadata")?;
        let name_end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
        if raw[name_end..].iter().any(|&byte| byte != 0) { bail!("invalid keystorage key name") }
        let name = std::str::from_utf8(&raw[..name_end]).context("keystorage key name is not UTF-8")?;
        let index = le32(data, item + 16)?;
        if name.is_empty() || index == 0 || !names.insert(name) || !indexes.insert(index) {
            bail!("duplicate keystorage key")
        }
        if name != "fw_key" { continue }
        if found.is_some() || le32(data, item + 20)? != 4 { bail!("invalid keystorage fw_key") }
        let at = header + slot * record;
        let key = data.get(at..at + P384).context("truncated keystorage fw_key")?;
        if data.get(at + P384..at + record).context("truncated keystorage record")?.iter().any(|&byte| byte != 0)
            || crc32fast::hash(key) != index || key[..20].iter().any(|&byte| byte != 0)
            || key[68..88].iter().any(|&byte| byte != 0) || key[136..].iter().any(|&byte| byte != 0) {
            bail!("invalid keystorage fw_key")
        }
        let mut point = [0; 97];
        point[0] = 4;
        point[1..49].copy_from_slice(&key[20..68]);
        point[49..].copy_from_slice(&key[88..136]);
        VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(point)?)
            .context("keystorage fw_key is not P-384")?;
        found = Some(key.to_vec());
    }
    Ok(Some(Keystorage { firmware_key: found }))
}

fn decode(index: &TarIndex, entry: &crate::archive::IndexedTarEntry) -> Result<Vec<u8>> {
    let region = index.region(entry)?;
    let mut magic = [0; 4];
    let lz4 = region.read_at(0, &mut magic)? == magic.len() && magic == LZ4_MAGIC;
    let reader: Box<dyn Read> = if lz4 { Box::new(lz4::Decoder::new(region.reader())?) } else { Box::new(region.reader()) };
    let mut output = Vec::new();
    reader.take(MAX_MEMBER + 1).read_to_end(&mut output)?;
    if output.len() as u64 > MAX_MEMBER { bail!("decoded BL member {} exceeds {MAX_MEMBER} bytes", entry.name) }
    Ok(output)
}

impl Catalog {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let source: Arc<dyn ReadAt> = Arc::new(File::open(path).with_context(|| format!("opening BL archive {}", path.display()))?);
        let index = TarIndex::open(source).with_context(|| format!("reading BL archive {}", path.display()))?;
        let mut members = Vec::new();
        for entry in index.entries().iter().filter(|entry| matches!(entry.kind, 0 | b'0')) {
            members.push((entry.name.clone(), decode(&index, entry).with_context(|| format!("decoding BL member {}", entry.name))?));
        }
        if members.is_empty() { bail!("BL archive contains no regular files") }
        let fld = members.iter().filter(|(name, _)| matches!(name.rsplit('/').next(), Some("fld.bin" | "fld.bin.lz4"))).collect::<Vec<_>>();
        if fld.len() != 1 { bail!("BL archive does not contain one FLD image") }
        let keys = crypto::sbl1_public_keys(&fld[0].1).context("FLD has no valid SBL1 keys")?;
        Self::from_decoded(members, Some(&keys))
    }

    fn from_decoded(members: impl IntoIterator<Item = (String, Vec<u8>)>, keys: Option<&[p384::ecdsa::VerifyingKey; 2]>) -> Result<Self> {
        let members = members.into_iter().collect::<Vec<_>>();
        let mut metadata = Vec::<(u8, String, usize, Template)>::new();
        let mut vbmeta = None;
        let mut firmware_key = None;
        let mut has_keystorage = false;
        let mut leaves = BTreeMap::new();
        let mut standalone = BTreeSet::new();
        for (name, data) in &members {
            if let Some(store) = keystorage(data).with_context(|| format!("reading keystorage in {name}"))? {
                if has_keystorage { bail!("BL archive contains multiple keystorage images") }
                has_keystorage = true;
                firmware_key = store.firmware_key;
            }
            if let Ok(parsed) = avb::parse(blob::bytes(data.clone())) {
                if parsed.footer.is_none() {
                    if vbmeta.is_some() { bail!("BL archive contains multiple standalone AVB images") }
                    standalone.insert(name.clone());
                    vbmeta = Some(data.clone());
                } else {
                    for descriptor in parsed.descriptors.iter().filter(|descriptor| matches!(descriptor.tag(), 1 | 2)) {
                        let part = descriptor.name()?.context("BL AVB descriptor has no partition name")?;
                        if leaves.insert(part.clone(), descriptor.clone()).is_some() { bail!("duplicate BL AVB descriptor {part}") }
                    }
                }
            }
            for at in data.windows(MARKER.len()).enumerate().filter_map(|(at, value)| (value == MARKER).then_some(at)) {
                let Some(trailer) = data.get(at..at + TRAILER) else { continue };
                let Ok(template) = Template::from_trailer(trailer) else { continue };
                if let Some(keys) = keys {
                    let key = template.key_type()? as usize;
                    let sig = at + 0x110;
                    let hash = Sha512::digest(&data[..sig]);
                    if !crypto::verify_padded(&keys[key], &hash, &data[sig..sig + 136]) { continue }
                }
                template.firmware_version().with_context(|| format!("reading CodeSigner version in {name} at {at:#x}"))?;
                metadata.push((if standalone.contains(name) { 0 } else { 1 }, name.clone(), at, template));
            }
        }
        if metadata.is_empty() { bail!("BL archive has no valid SignerVer03 metadata") }
        let vbmeta_data = vbmeta.as_ref().context("BL archive has no standalone vbmeta.img")?;
        let parsed = avb::parse(blob::bytes(vbmeta_data.clone()))?;
        let mut matched = BTreeSet::new();
        for descriptor in parsed.descriptors.iter().filter(|descriptor| matches!(descriptor.tag(), 1 | 2)) {
            let part = descriptor.name()?.context("BL vbmeta descriptor has no partition name")?;
            if let Some(leaf) = leaves.get(&part) {
                if descriptor != leaf { bail!("BL vbmeta descriptor does not match {part}") }
                matched.insert(part);
            }
        }
        let missing = leaves.keys().filter(|part| !matched.contains(*part)).collect::<Vec<_>>();
        if !missing.is_empty() { bail!("BL vbmeta is missing descriptors: {missing:?}") }
        let versions = metadata.iter().map(|(_, _, _, template)| template.firmware_version()).collect::<Result<BTreeSet<_>>>()?;
        if versions.len() != 1 { bail!("BL images contain inconsistent firmware versions: {versions:?}") }
        let rollbacks = metadata.iter().map(|(_, _, _, template)| template.rollback()).collect::<Result<BTreeSet<_>>>()?;
        if rollbacks.len() != 1 { bail!("BL images contain inconsistent rollback indices: {rollbacks:?}") }
        metadata.sort_by(|left, right| (&left.0, &left.1, left.2).cmp(&(&right.0, &right.1, right.2)));
        let base = metadata[0].3.clone();
        let mut templates = BTreeMap::new();
        for (_, _, _, template) in metadata {
            templates.entry(template.key_type()?).or_insert(template);
        }
        for key_type in [0, 1] {
            if !templates.contains_key(&key_type) { templates.insert(key_type, base.with_key_type(key_type)?); }
        }
        Ok(Self {
            version: versions.into_iter().next().context("BL firmware version is missing")?,
            templates,
            vbmeta,
            firmware_key,
        })
    }

    pub(super) fn version(&self) -> &str { &self.version }

    pub(super) fn normal(&self, key_type: u32) -> Result<&Template> {
        self.templates.get(&key_type).with_context(|| format!("BL archive has no ST2 key type {key_type} data"))
    }

    pub(super) fn sparse_seed(&self, key_type: u32, block_size: usize) -> Result<Vec<u8>> {
        self.normal(key_type)?.sparse_seed(block_size)
    }

    pub(super) fn vbmeta(&self) -> Option<Blob> { self.vbmeta.clone().map(blob::bytes) }

    pub(super) fn firmware_key(&self) -> Option<&[u8]> { self.firmware_key.as_deref() }

    pub(super) fn require_firmware_key(&self, keys: &crypto::Keys) -> Result<()> {
        let actual = self.firmware_key.as_ref().context("BL keystorage has no fw_key; resign the BL with the current signer")?;
        let expected = crypto::public_blob(&keys.ree);
        if actual != &expected { bail!("BL keystorage fw_key does not match the configured REE key") }
        Ok(())
    }
}
