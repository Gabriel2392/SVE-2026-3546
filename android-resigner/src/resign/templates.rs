use std::{collections::{BTreeMap, BTreeSet}, fs::File, io::Read, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use sha2_10::{Digest, Sha512};

use crate::{archive::TarIndex, io::ReadAt};
use super::{avb, blob::{self, Blob}, codesigner::Template, crypto};

const LZ4_MAGIC: [u8; 4] = 0x184d_2204u32.to_le_bytes();
const MAX_MEMBER: u64 = 128 << 20;
const MARKER: &[u8] = b"SignerVer03";
const TRAILER: usize = 0x310;

#[derive(Clone)]
pub(super) struct Catalog {
    version: String,
    templates: BTreeMap<u32, Template>,
    vbmeta: Option<Vec<u8>>,
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
        let keys = members.iter().filter_map(|(_, data)| crypto::sbl1_public_keys(data).ok()).collect::<Vec<_>>();
        if keys.len() != 1 { bail!("BL archive does not contain one valid SBL1 key source") }
        Self::from_decoded(members, Some(&keys[0]))
    }

    fn from_decoded(members: impl IntoIterator<Item = (String, Vec<u8>)>, keys: Option<&[p384::ecdsa::VerifyingKey; 2]>) -> Result<Self> {
        let members = members.into_iter().collect::<Vec<_>>();
        let mut metadata = Vec::<(u8, String, usize, Template)>::new();
        let mut vbmeta = None;
        let mut leaves = BTreeMap::new();
        let mut standalone = BTreeSet::new();
        for (name, data) in &members {
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
}
