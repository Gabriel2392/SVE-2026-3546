use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2_10::{Digest, Sha256};

use crate::{archive::TarIndex, io::ReadAt};
use super::{avb::{self, Parsed}, blob, codesigner::{self, Template}, incremental};

const KIND: &str = "android-resigner-stock";
const FORMAT: u32 = 1;
const MAX_STOCK: u64 = 16 << 20;
const MAX_AVB_METADATA: usize = 4 << 20;
const MAX_RECORDS: usize = 128;
const MAX_CAPACITY: u64 = 16 << 40;
pub(super) const MEMBER: &str = "android-resigner.json";

fn digest(data: &[u8]) -> String { hex::encode(Sha256::digest(data)) }
pub(super) fn sha256_bytes(data: &[u8]) -> String { digest(data) }

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_firmware(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn decode_hex(value: &str, description: &str, limit: usize) -> Result<Vec<u8>> {
    if value.len() & 1 != 0 || value.len() / 2 > limit { bail!("invalid or oversized {description}") }
    hex::decode(value).with_context(|| format!("invalid hexadecimal {description}"))
}

pub(super) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hash = Sha256::new(); let mut buffer = vec![0; 8 << 20];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceHashes {
    pub bl: String,
    pub ap: String,
    pub cp: String,
    pub csc: String,
}

impl SourceHashes {
    pub(super) fn from_paths(bl: &Path, ap: &Path, cp: &Path, csc: &Path) -> Result<Self> {
        Ok(Self { bl: sha256_file(bl)?, ap: sha256_file(ap)?, cp: sha256_file(cp)?, csc: sha256_file(csc)? })
    }

    pub(super) fn from_unified(bl: &Path, archive: &Path) -> Result<Self> {
        let bl = sha256_file(bl)?;
        let archive = sha256_file(archive)?;
        Ok(Self { bl, ap: archive.clone(), cp: archive.clone(), csc: archive })
    }

    fn validate(&self) -> Result<()> {
        for value in [&self.bl, &self.ap, &self.cp, &self.csc] {
            if !valid_digest(value) { bail!("stock contains an invalid source SHA-256") }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CodeSignerForm { Normal, Sparse }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CodeSignerRecord {
    form: CodeSignerForm,
    key_type: u32,
    rollback: u32,
    firmware: String,
    data: String,
}

pub(super) enum CodeSignerMaterial { Normal(Template), Sparse(Vec<u8>) }

impl CodeSignerRecord {
    pub(super) fn normal(template: &Template) -> Result<Self> {
        Self::from_template(CodeSignerForm::Normal, template, template.trailer())
    }

    pub(super) fn sparse(block: &[u8]) -> Result<Self> {
        if block.len() != 4096 { bail!("sparse CodeSigner stock block must be exactly 4096 bytes") }
        let template = Template::from_sparse_seed(block)?;
        Self::from_template(CodeSignerForm::Sparse, &template, block.to_vec())
    }

    fn from_template(form: CodeSignerForm, template: &Template, data: Vec<u8>) -> Result<Self> {
        Ok(Self {
            form,
            key_type: template.key_type()?,
            rollback: template.rollback()?,
            firmware: template.firmware_version()?,
            data: hex::encode(data),
        })
    }

    pub(super) fn material(&self) -> Result<CodeSignerMaterial> {
        match self.form {
            CodeSignerForm::Normal => {
                let data = decode_hex(&self.data, "normal CodeSigner data", 0x310)?;
                if data.len() != 0x310 { bail!("normal CodeSigner stock data is not 0x310 bytes") }
                let template = Template::from_trailer(&data)?;
                self.check_template(&template)?;
                Ok(CodeSignerMaterial::Normal(template))
            }
            CodeSignerForm::Sparse => {
                let data = decode_hex(&self.data, "sparse CodeSigner data", 4096)?;
                if data.len() != 4096 { bail!("sparse CodeSigner stock data is not 4096 bytes") }
                let template = Template::from_sparse_seed(&data)?;
                self.check_template(&template)?;
                Ok(CodeSignerMaterial::Sparse(data))
            }
        }
    }

    fn check_template(&self, template: &Template) -> Result<()> {
        if self.key_type > 1 || template.key_type()? != self.key_type || template.rollback()? != self.rollback
            || template.firmware_version()? != self.firmware {
            bail!("CodeSigner stock metadata does not match its encoded data")
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AvbRecord {
    image_size: u64,
    block_size: u64,
    metadata_offset: u64,
    metadata: String,
    footer: Option<String>,
}

impl AvbRecord {
    pub(super) fn from_parsed(parsed: &Parsed) -> Result<Self> {
        let metadata_offset = parsed.footer.as_ref().map_or(0, |footer| footer.vbmeta_offset);
        let metadata_size = 256u64.checked_add(parsed.header.auth_size)
            .and_then(|size| size.checked_add(parsed.header.aux_size)).context("AVB metadata size overflow")?;
        if metadata_size > MAX_AVB_METADATA as u64 { bail!("AVB stock metadata exceeds {MAX_AVB_METADATA} bytes") }
        let mut metadata = vec![0; metadata_size as usize];
        parsed.source.read_exact_at(metadata_offset, &mut metadata)?;
        let footer = if parsed.footer.is_some() {
            let mut raw = [0; 64]; parsed.source.read_exact_at(parsed.image_size - 64, &mut raw)?; Some(hex::encode(raw))
        } else { None };
        let record = Self {
            image_size: parsed.image_size,
            block_size: parsed.block_size,
            metadata_offset,
            metadata: hex::encode(metadata),
            footer,
        };
        record.parsed()?;
        Ok(record)
    }

    pub(super) fn parsed(&self) -> Result<Parsed> {
        if self.image_size == 0 || self.image_size > MAX_CAPACITY || self.block_size != 4096 {
            bail!("invalid AVB stock image geometry")
        }
        let metadata = decode_hex(&self.metadata, "AVB metadata", MAX_AVB_METADATA)?;
        if metadata.len() < 256 || self.metadata_offset.checked_add(metadata.len() as u64).is_none_or(|end| end > self.image_size) {
            bail!("AVB stock metadata exceeds its image")
        }
        let metadata_len = metadata.len();
        let mut overlays = vec![(self.metadata_offset, blob::bytes(metadata))];
        if let Some(value) = &self.footer {
            let footer = decode_hex(value, "AVB footer", 64)?;
            if footer.len() != 64 || self.image_size < 64 { bail!("invalid AVB stock footer") }
            overlays.push((self.image_size - 64, blob::bytes(footer)));
        } else if self.metadata_offset != 0 {
            bail!("standalone AVB metadata must begin at offset zero")
        }
        let parsed = avb::parse(blob::overlay(blob::zeroes(self.image_size), overlays)?)?;
        let actual = 256u64 + parsed.header.auth_size + parsed.header.aux_size;
        if actual != metadata_len as u64 || parsed.block_size != self.block_size || parsed.footer.is_some() != self.footer.is_some() {
            bail!("reconstructed AVB stock data changed layout")
        }
        Ok(parsed)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageRecord {
    partition: String,
    capacity: u64,
    codesigner: Option<CodeSignerRecord>,
    avb_template: Option<AvbRecord>,
    #[serde(default)]
    marker: bool,
}

impl ImageRecord {
    pub(super) fn new(partition: impl Into<String>, capacity: u64,
                      codesigner: Option<CodeSignerRecord>, avb_template: Option<AvbRecord>) -> Self {
        Self { partition: partition.into(), capacity, codesigner, avb_template, marker: false }
    }
    pub(super) fn partition(&self) -> &str { &self.partition }
    pub(super) fn capacity(&self) -> u64 { self.capacity }
    pub(super) fn codesigner(&self) -> Option<&CodeSignerRecord> { self.codesigner.as_ref() }
    pub(super) fn avb_template(&self) -> Option<&AvbRecord> { self.avb_template.as_ref() }
    pub(super) fn with_codesigner(mut self, value: CodeSignerRecord) -> Self { self.codesigner = Some(value); self }
    pub(super) fn generated(mut self) -> Self { self.avb_template = None; self }
    pub(super) fn with_marker(mut self, marker: bool) -> Self { self.marker = marker; self }
    pub(super) fn marker(&self) -> bool { self.marker }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StockData {
    soc: String,
    firmware: String,
    rollback: u32,
    config_sha256: String,
    sources: SourceHashes,
    images: BTreeMap<String, ImageRecord>,
    logical: BTreeMap<String, ImageRecord>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    kind: String,
    format: u32,
    payload: StockData,
    sha256: String,
}

pub(super) struct Stock { data: StockData }

impl Stock {
    pub(super) fn new(soc: impl Into<String>, firmware: impl Into<String>, rollback: u32,
                      config_sha256: impl Into<String>, sources: SourceHashes) -> Result<Self> {
        let stock = Self { data: StockData {
            soc: soc.into(), firmware: firmware.into(), rollback,
            config_sha256: config_sha256.into(), sources,
            images: BTreeMap::new(), logical: BTreeMap::new(),
        }};
        stock.validate(false)?; Ok(stock)
    }

    pub(super) fn firmware(&self) -> &str { &self.data.firmware }
    pub(super) fn soc(&self) -> &str { &self.data.soc }
    pub(super) fn rollback(&self) -> u32 { self.data.rollback }
    pub(super) fn image(&self, name: &str) -> Result<&ImageRecord> {
        self.data.images.get(name).with_context(|| format!("stock data has no image named {name}"))
    }
    pub(super) fn record(&self, name: &str) -> Result<&ImageRecord> {
        self.data.images.get(name).or_else(|| self.data.logical.get(name))
            .with_context(|| format!("stock has no signing record {name}"))
    }
    pub(super) fn has(&self, name: &str) -> bool { self.data.images.contains_key(name) || self.data.logical.contains_key(name) }
    pub(super) fn generated_salt(&self, partition: &str) -> [u8; 32] {
        let mut hash = Sha256::new(); hash.update(b"android-resigner-avb-v1\0");
        hash.update(self.data.firmware.as_bytes()); hash.update([0]); hash.update(partition.as_bytes());
        hash.update([0]); hash.update(self.data.sources.ap.as_bytes()); hash.finalize().into()
    }

    pub(super) fn insert_image(&mut self, name: impl Into<String>, record: ImageRecord) -> Result<()> {
        let name = name.into();
        if self.data.logical.contains_key(&name) || self.data.images.contains_key(&name) { bail!("duplicate stock record {name}") }
        self.data.images.insert(name.clone(), record);
        if let Err(error) = self.validate(false) { self.data.images.remove(&name); return Err(error) }
        Ok(())
    }

    pub(super) fn insert_logical(&mut self, name: impl Into<String>, record: ImageRecord) -> Result<()> {
        let name = name.into();
        if self.data.images.contains_key(&name) || self.data.logical.contains_key(&name) { bail!("duplicate stock record {name}") }
        self.data.logical.insert(name.clone(), record);
        if let Err(error) = self.validate(false) { self.data.logical.remove(&name); return Err(error) }
        Ok(())
    }

    pub(super) fn require_config(&self, config: &[u8]) -> Result<()> {
        if digest(config) != self.data.config_sha256 { bail!("stock was created for a different config") }
        Ok(())
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.validate(true)?;
        let payload = serde_json::to_vec(&self.data)?;
        let envelope = Envelope { kind: KIND.into(), format: FORMAT, payload: self.data.clone(), sha256: digest(&payload) };
        let encoded = serde_json::to_vec_pretty(&envelope)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_STOCK { bail!("stock has invalid size") }
        Ok(encoded)
    }

    pub(super) fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data.len() as u64 > MAX_STOCK { bail!("stock has invalid size") }
        let envelope: Envelope = serde_json::from_slice(data).context("invalid stock JSON")?;
        if envelope.kind != KIND || envelope.format != FORMAT { bail!("unsupported stock kind or format") }
        let payload = serde_json::to_vec(&envelope.payload)?;
        if !valid_digest(&envelope.sha256) || digest(&payload) != envelope.sha256 { bail!("stock payload digest mismatch") }
        let stock = Self { data: envelope.payload }; stock.validate(true)?; Ok(stock)
    }

    pub(super) fn from_archive(path: &Path) -> Result<Option<Self>> {
        incremental::parse_trailer(path)?;
        let source: Arc<dyn ReadAt> = Arc::new(File::open(path)?);
        let index = TarIndex::open(source).with_context(|| format!("reading {}", path.display()))?;
        let found = index.entries().iter().filter(|entry| entry.name == MEMBER).collect::<Vec<_>>();
        if found.is_empty() { return Ok(None) }
        if found.len() != 1 { bail!("archive contains more than one {MEMBER} file") }
        let entry = found[0];
        if !matches!(entry.kind, 0 | b'0') { bail!("{MEMBER} is not a regular file") }
        if entry.size == 0 || entry.size > MAX_STOCK { bail!("{MEMBER} has invalid size") }
        let region = index.region(entry)?;
        let mut data = vec![0; entry.size as usize]; region.read_exact_at(0, &mut data)?;
        Ok(Some(Self::decode(&data)?))
    }

    fn validate(&self, require_images: bool) -> Result<()> {
        if !safe_name(&self.data.soc) || !valid_firmware(&self.data.firmware)
            || !valid_digest(&self.data.config_sha256) { bail!("invalid stock identity") }
        self.data.sources.validate()?;
        let count = self.data.images.len().checked_add(self.data.logical.len()).context("stock record count overflow")?;
        if count > MAX_RECORDS || (require_images && self.data.images.is_empty()) { bail!("invalid stock record count") }
        let mut names = BTreeSet::new();
        for (logical, records) in [(false, &self.data.images), (true, &self.data.logical)] {
            for (name, record) in records {
                if !safe_name(name) || !safe_name(&record.partition) || !names.insert(name) { bail!("invalid or duplicate stock record {name:?}") }
                if record.capacity == 0 || record.capacity > MAX_CAPACITY { bail!("{name}: invalid partition capacity") }
                if logical && record.codesigner.is_some() { bail!("logical stock record {name} unexpectedly has CodeSigner metadata") }
                if let Some(code) = &record.codesigner {
                    code.material()?;
                    if !codesigner::same_build_family(&self.data.firmware, &code.firmware) || code.rollback != self.data.rollback {
                        bail!("{name}: CodeSigner data is from another firmware version")
                    }
                }
                if let Some(template) = &record.avb_template {
                    let parsed = template.parsed()?;
                    if parsed.image_size != record.capacity { bail!("{name}: AVB image size differs from stock capacity") }
                    if parsed.footer.is_some() {
                        let integrity = parsed.descriptors.iter().filter(|descriptor| matches!(descriptor.tag(), 1 | 2))
                            .map(|descriptor| descriptor.name()).collect::<Result<Vec<_>>>()?;
                        if integrity.len() != 1 || integrity[0].as_deref() != Some(record.partition.as_str()) {
                            bail!("{name}: AVB integrity descriptor does not match partition {}", record.partition)
                        }
                    }
                }
                if record.codesigner.is_none() && record.avb_template.is_none() && !logical {
                    continue
                }
            }
        }
        Ok(())
    }
}
