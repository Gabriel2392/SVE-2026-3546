use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};

use super::{
    avb::{self, Descriptor, GenerationPolicy, IntegrityKind, Parsed},
    blob::{self, Blob}, boot, codesigner::{self, Template},
    config::{AvbGenerationPolicy, AvbKind, CodeSignerKind, Filesystem, ImageRule, KeyPolicy, SaltPolicy},
    crypto::Keys, erofs, f2fs,
    stock::{AvbRecord, CodeSignerMaterial, CodeSignerRecord, ImageRecord, Stock},
    sparse,
};

impl AvbGenerationPolicy {
    pub(super) fn avb(&self) -> GenerationPolicy {
        GenerationPolicy {
            data_block: self.data_block, hash_block: self.hash_block, fec_roots: self.fec_roots,
            flags: self.flags, rollback_index: self.rollback_index, rollback_location: self.rollback_location,
            footer_version_major: self.footer_version_major, footer_version_minor: self.footer_version_minor,
            release: self.release.clone(),
        }
    }

    fn salt(&self, stock: &Stock, partition: &str) -> Result<[u8; 32]> {
        match &self.salt {
            SaltPolicy::StockDerived => Ok(stock.generated_salt(partition)),
            SaltPolicy::Zero => Ok([0; 32]),
            SaltPolicy::Fixed { hex } => {
                let raw = hex::decode(hex).context("invalid fixed AVB salt")?;
                raw.try_into().map_err(|_| anyhow::anyhow!("fixed AVB salt must be exactly 32 bytes"))
            }
        }
    }
}

pub(super) struct SignedImage {
    pub image: Blob,
    pub descriptor: Option<Descriptor>,
    pub partition: String,
    pub metadata: BuildMetadata,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct BuildMetadata {
    pub synthesized_codesigner: bool,
    pub synthesized_avb: bool,
    pub nested_firmware: usize,
    pub code_key: Option<u32>,
}

const MARKER: &[u8] = b"SEANDROIDENFORCE";

fn ends(source: &Blob) -> Result<bool> {
    let len = source.len()?;
    if len < MARKER.len() as u64 { return Ok(false) }
    let mut data = vec![0; MARKER.len()];
    source.read_exact_at(len - MARKER.len() as u64, &mut data)?;
    Ok(data == MARKER)
}

fn set_marker(source: Blob, required: bool) -> Result<Blob> {
    match (ends(&source)?, required) {
        (false, true) => Ok(blob::Concat::blob([source, blob::bytes(MARKER.to_vec())])?),
        (true, false) => Ok(blob::Prefix::blob(source.clone(), source.len()? - MARKER.len() as u64)?),
        _ => Ok(source),
    }
}

fn code_key(rule: &ImageRule, template: Template) -> Result<Template> {
    match rule.key {
        KeyPolicy::Auto => Ok(template),
        KeyPolicy::Tee => template.with_key_type(0),
        KeyPolicy::Ree => template.with_key_type(1),
    }
}

fn stock_template(record: &ImageRecord, expected: CodeSignerKind) -> Result<Template> {
    let value = record.codesigner().context("stock data has no CodeSigner wrapper data")?;
    match (expected, value.material()?) {
        (CodeSignerKind::Normal, CodeSignerMaterial::Normal(template)) => Ok(template),
        (CodeSignerKind::Normal, CodeSignerMaterial::Sparse(block)) => Template::from_sparse_seed(&block),
        (CodeSignerKind::Sparse, CodeSignerMaterial::Normal(template)) => Ok(template),
        (CodeSignerKind::Sparse, CodeSignerMaterial::Sparse(block)) => Template::from_sparse_seed(&block),
        _ => bail!("stock CodeSigner data is incompatible with the image rule"),
    }
}

fn sparse_seed(source: &Blob, rule: &ImageRule, record: &ImageRecord, metadata: &mut BuildMetadata) -> Result<Vec<u8>> {
    let mut first = vec![0; 4096]; source.read_exact_at(0, &mut first)?;
    let present = codesigner::sparse_template(source).is_ok();
    if !present && !rule.synthesize_missing_wrappers { bail!("sparse CodeSigner data is missing") }
    metadata.synthesized_codesigner = !present;
    let template = stock_template(record, CodeSignerKind::Sparse)?;
    let template = code_key(rule, template)?;
    let generated = template.sparse_seed(4096)?;
    first[..0x400].copy_from_slice(&generated[..0x400]);
    Ok(first)
}

fn existing_avb(source: &Blob, kind: AvbKind) -> Result<Option<Parsed>> {
    if kind == AvbKind::None { return Ok(None) }
    let len = source.len()?;
    match kind {
        AvbKind::Standalone => {
            let mut magic = [0; 4]; source.read_exact_at(0, &mut magic)?;
            if &magic == b"AVB0" { Ok(Some(avb::parse(source.clone())?)) } else { Ok(None) }
        }
        AvbKind::Hash | AvbKind::Hashtree => {
            if avb::payload_boundary(source, len)?.is_some() { Ok(Some(avb::parse(source.clone())?)) } else { Ok(None) }
        }
        AvbKind::None => unreachable!(),
    }
}

fn input_avb(source: &Blob) -> Result<Option<u64>> { avb::payload_boundary(source, source.len()?) }

fn integrity_kind(rule: &ImageRule) -> Result<IntegrityKind> {
    match rule.avb {
        AvbKind::Hash => Ok(IntegrityKind::Hash),
        AvbKind::Hashtree => Ok(IntegrityKind::Hashtree),
        value => bail!("{value:?} is not a footer AVB integrity mode"),
    }
}

fn check_avb_kind(template: &Parsed, rule: &ImageRule) -> Result<()> {
    if rule.avb == AvbKind::Standalone {
        if template.footer.is_some() { bail!("standalone vbmeta unexpectedly has an AVB footer") }
        return Ok(())
    }
    let found = template.descriptors.iter().filter(|item| matches!(item.tag(), 1 | 2)).collect::<Vec<_>>();
    if found.len() != 1 || found[0].name()?.as_deref() != Some(rule.partition.as_str()) {
        bail!("AVB integrity descriptor does not match {}", rule.partition)
    }
    let want = match rule.avb { AvbKind::Hash => 2, AvbKind::Hashtree => 1, _ => return Ok(()) };
    if found[0].tag() != want { bail!("AVB descriptor type does not match the image rule") }
    Ok(())
}

fn avb_template(stock: &Stock, record: &ImageRecord, rule: &ImageRule,
                payload_size: u64, policy: &AvbGenerationPolicy,
                metadata: &mut BuildMetadata) -> Result<Parsed> {
    if let Some(template) = record.avb_template() {
        let template = template.parsed()?; check_avb_kind(&template, rule)?; return Ok(template)
    }
    if !rule.synthesize_missing_wrappers { bail!("AVB footer is missing and synthesis is disabled") }
    metadata.synthesized_avb = true;
    let salt = policy.salt(stock, &rule.partition)?;
    avb::generated_template(integrity_kind(rule)?, &rule.partition, record.capacity(), payload_size, &salt, &policy.avb())
}

fn avb_payload(source: Blob, boundary: Option<u64>) -> Result<Blob> {
    boundary.map_or(Ok(source.clone()), |size| Ok(blob::region(source, 0, size)?))
}

fn resign_filesystem(mut payload: Blob, rule: &Filesystem, keys: &Keys, description: &str) -> Result<(Blob, usize)> {
    eprintln!("Processing {description} for firmware files");
    if f2fs::present(&payload)? {
        if !rule.preserve_stock.is_empty() || !rule.sign_firmware.is_empty() || !rule.remove.is_empty() {
            bail!("explicit file edits are unsupported for independent F2FS signing")
        }
        return if rule.discover_firmware { f2fs::resign(payload, keys, description) } else { Ok((payload, 0)) }
    }
    if !rule.preserve_stock.is_empty() { bail!("independent signing cannot preserve files without a separate stock filesystem") }
    for path in &rule.remove { payload = erofs::remove(payload, path)?; }
    let mut firmware = rule.sign_firmware.iter().cloned().collect::<BTreeSet<_>>();
    let detected = if rule.discover_firmware {
        let value = erofs::signed_firmware_paths(payload.clone())?; firmware.extend(value.iter().cloned()); value
    } else { Vec::new() };
    for path in &firmware {
        let mut data = erofs::read(payload.clone(), path)?;
        let key = codesigner::sign_firmware(&mut data, keys, &format!("{description}:/{path}"))?;
        codesigner::verify_firmware(&data, keys, &format!("{description}:/{path}"))?;
        payload = erofs::replace(payload, path, &data)?;
        eprintln!("CodeSigned {description}:{path} ({})", if key == 0 { "TEE" } else { "REE" });
    }
    if rule.discover_firmware {
        let after = erofs::signed_firmware_paths(payload.clone())?;
        if after != detected { bail!("signed EROFS firmware set changed during independent signing") }
        for path in &after {
            codesigner::verify_firmware(&erofs::read(payload.clone(), path)?, keys, &format!("{description}:/{path}"))?;
        }
    }
    Ok((payload, firmware.len()))
}

fn add_avb(payload: Blob, stock: &Stock, record: &ImageRecord, rule: &ImageRule,
           keys: &Keys, policy: &AvbGenerationPolicy,
           metadata: &mut BuildMetadata) -> Result<(Blob, Option<Descriptor>)> {
    match rule.avb {
        AvbKind::None => Ok((payload, None)),
        AvbKind::Hash | AvbKind::Hashtree => {
            let template = avb_template(stock, record, rule, payload.len()?, policy, metadata)?;
            let (image, descriptor) = avb::add_footer(payload, &template, keys)?;
            Ok((image, Some(descriptor)))
        }
        AvbKind::Standalone => bail!("standalone vbmeta signing is handled by build-vbmeta"),
    }
}

fn sign_normal(name: &str, source: Blob, stock: &Stock, record: &ImageRecord,
               rule: &ImageRule, keys: &Keys, policy: &AvbGenerationPolicy, nested: bool) -> Result<SignedImage> {
    let mut metadata = BuildMetadata::default();
    let boundary = input_avb(&source)?.unwrap_or(source.len()?);
    let present = codesigner::present(&source, boundary)?;
    if !present && !rule.synthesize_missing_wrappers { bail!("{name}: CodeSigner wrapper is missing and synthesis is disabled") }
    metadata.synthesized_codesigner = !present;
    let template = code_key(rule, stock_template(record, CodeSignerKind::Normal)?)?;
    metadata.code_key = Some(template.key_type()?);
    let raw_end = if present { boundary.checked_sub(codesigner::NORMAL as u64).context("CodeSigner boundary underflow")? } else { boundary };
    let mut payload = blob::region(source, 0, raw_end)?;
    if nested && let Some(ramdisk) = &rule.ramdisk {
        eprintln!("Processing {name} for firmware files");
        payload = boot::repack(payload, ramdisk, keys, name)?;
    }
    if nested && let Some(filesystem) = &rule.filesystem {
        (payload, metadata.nested_firmware) = resign_filesystem(payload, filesystem, keys, name)?;
    }
    payload = set_marker(payload, record.marker())?;
    let signed = codesigner::append(payload, &template, name, keys)?;
    let (image, descriptor) = add_avb(signed, stock, record, rule, keys, policy, &mut metadata)?;
    Ok(SignedImage { image, descriptor, partition: rule.partition.clone(), metadata })
}

fn sign_without_codesigner(name: &str, source: Blob, stock: &Stock, record: &ImageRecord,
                           rule: &ImageRule, keys: &Keys, policy: &AvbGenerationPolicy, nested: bool) -> Result<SignedImage> {
    let mut metadata = BuildMetadata::default();
    let boundary = input_avb(&source)?;
    let mut payload = avb_payload(source, boundary)?;
    if nested && let Some(filesystem) = &rule.filesystem {
        (payload, metadata.nested_firmware) = resign_filesystem(payload, filesystem, keys, name)?;
    }
    let (image, descriptor) = add_avb(payload, stock, record, rule, keys, policy, &mut metadata)?;
    Ok(SignedImage { image, descriptor, partition: rule.partition.clone(), metadata })
}

fn sign_sparse(name: &str, source: Blob, stock: &Stock, record: &ImageRecord,
               rule: &ImageRule, keys: &Keys, policy: &AvbGenerationPolicy, nested: bool) -> Result<SignedImage> {
    let mut metadata = BuildMetadata::default();
    let raw = sparse::decode_if_sparse(source)?;
    let seed = sparse_seed(&raw, rule, record, &mut metadata)?;
    metadata.code_key = Some(Template::from_sparse_seed(&seed)?.key_type()?);
    let boundary = input_avb(&raw)?;
    let mut payload = avb_payload(raw, boundary)?;
    let mut normalized = vec![0; 0x400];
    if !matches!(rule.avb, AvbKind::None) { normalized[0x300..0x400].copy_from_slice(&seed[0x300..0x400]); }
    payload = blob::patch(payload, vec![(0, normalized)])?;
    if nested && let Some(filesystem) = &rule.filesystem {
        (payload, metadata.nested_firmware) = resign_filesystem(payload, filesystem, keys, name)?;
    }
    let (raw, descriptor) = add_avb(payload, stock, record, rule, keys, policy, &mut metadata)?;
    let image = codesigner::sign_sparse(sparse::encode(raw, 4096)?, &seed, name, keys)?;
    Ok(SignedImage { image, descriptor, partition: rule.partition.clone(), metadata })
}

fn build(name: &str, source: Blob, stock: &Stock, rule: &ImageRule,
         keys: &Keys, policy: &AvbGenerationPolicy, nested: bool) -> Result<SignedImage> {
    let record = stock.record(name)?;
    if record.partition() != rule.partition { bail!("{name}: stock/config partition mismatch") }
    match rule.codesigner {
        CodeSignerKind::Normal => sign_normal(name, source, stock, record, rule, keys, policy, nested),
        CodeSignerKind::Sparse => sign_sparse(name, source, stock, record, rule, keys, policy, nested),
        CodeSignerKind::None => sign_without_codesigner(name, source, stock, record, rule, keys, policy, nested),
        CodeSignerKind::StandaloneVbmeta => bail!("use build-vbmeta for standalone vbmeta images"),
    }
}

pub(super) fn sign(name: &str, source: Blob, stock: &Stock, rule: &ImageRule,
                   keys: &Keys, policy: &AvbGenerationPolicy) -> Result<SignedImage> {
    build(name, source, stock, rule, keys, policy, true)
}

pub(super) fn wrap(name: &str, source: Blob, stock: &Stock, rule: &ImageRule,
                   keys: &Keys, policy: &AvbGenerationPolicy) -> Result<SignedImage> {
    build(name, source, stock, rule, keys, policy, false)
}

pub(super) fn record_from_stock(name: &str, source: Blob, rule: &ImageRule, capacity: Option<u64>) -> Result<ImageRecord> {
    let (parsed, codesigner, inferred, marker) = match rule.codesigner {
        CodeSignerKind::Normal => {
            let parsed = existing_avb(&source, rule.avb)?;
            let boundary = parsed.as_ref().and_then(|item| item.footer.as_ref()).map_or(source.len()?, |footer| footer.original_size);
            let codesigner = if codesigner::present(&source, boundary)? {
                Some(CodeSignerRecord::normal(&codesigner::extract(&source, boundary)?)?)
            } else if !rule.synthesize_missing_wrappers { bail!("{name}: stock image has no required CodeSigner wrapper") }
            else { None };
            let inferred = parsed.as_ref().map_or(source.len()?, |item| item.image_size);
            let raw = if codesigner.is_some() { boundary.checked_sub(codesigner::NORMAL as u64).context("CodeSigner boundary underflow")? } else { boundary };
            let marker = ends(&blob::region(source.clone(), 0, raw)?)?;
            (parsed, codesigner, inferred, marker)
        }
        CodeSignerKind::Sparse => {
            let raw = sparse::decode_if_sparse(source)?;
            let codesigner = if let Ok(block) = codesigner::sparse_template(&raw) { Some(CodeSignerRecord::sparse(&block)?) }
            else if !rule.synthesize_missing_wrappers { bail!("{name}: stock image has no required sparse CodeSigner wrapper") }
            else { None };
            let parsed = existing_avb(&raw, rule.avb)?;
            let inferred = parsed.as_ref().map_or(raw.len()?, |item| item.image_size);
            (parsed, codesigner, inferred, false)
        }
        CodeSignerKind::None => {
            let parsed = existing_avb(&source, rule.avb)?;
            let inferred = parsed.as_ref().map_or(source.len()?, |item| item.image_size);
            (parsed, None, inferred, false)
        }
        CodeSignerKind::StandaloneVbmeta => {
            let parsed = existing_avb(&source, AvbKind::Standalone)?;
            let codesigner = if codesigner::present(&source, source.len()?)? {
                Some(CodeSignerRecord::normal(&codesigner::extract(&source, source.len()?)?)?)
            } else if !rule.synthesize_missing_wrappers { bail!("{name}: stock vbmeta has no CodeSigner wrapper") }
            else { None };
            (parsed, codesigner, source.len()?, false)
        }
    };
    if !matches!(rule.avb, AvbKind::None) && parsed.is_none() && !rule.synthesize_missing_wrappers {
        bail!("{name}: stock image has no required AVB metadata")
    }
    if let Some(value) = &parsed { check_avb_kind(value, rule)?; }
    let avb_template = parsed.as_ref().map(AvbRecord::from_parsed).transpose()?;
    Ok(ImageRecord::new(&rule.partition, capacity.unwrap_or(inferred), codesigner, avb_template).with_marker(marker))
}
