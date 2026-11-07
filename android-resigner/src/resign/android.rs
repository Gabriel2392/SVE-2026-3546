use std::{collections::{BTreeMap, BTreeSet}, path::Path};

use anyhow::{bail, Context, Result};

use crate::lp;
use super::{avb, blob::{self, Blob}, boot, codesigner, config::{AvbKind, CodeSignerKind, Config, ImageRule, KeyPolicy}, crypto::Keys, erofs, f2fs, input::ImageSource, stock::Stock, sparse, templates::Catalog};

pub struct Built { pub images: BTreeMap<String, Blob>, pub descriptors: BTreeMap<String, avb::Descriptor> }

pub(super) struct UpdatedSuper {
    pub image: Blob,
    pub logical: BTreeMap<String, (Blob, avb::Descriptor)>,
}

struct SuperBuilt { image: Blob, descriptors: BTreeMap<String, avb::Descriptor> }

struct Input { metadata_bytes: Vec<u8>, metadata: lp::Metadata, raw: Blob }

fn mode(key: u32) -> &'static str { if key == 0 { "TEE" } else { "REE" } }

fn firmware(base: &str, alternate: Option<&str>, candidate: &str) -> bool {
    codesigner::same_build_family(base, candidate)
        || alternate.is_some_and(|value| codesigner::same_build_family(value, candidate))
}

fn data_size(descriptor: &avb::Descriptor) -> Result<u64> {
    if let Some(value) = descriptor.hash()? { return Ok(value.image_size) }
    if let Some(value) = descriptor.tree()? { return Ok(value.image_size) }
    bail!("logical partition has no AVB integrity descriptor")
}

fn nonzero(source: &Blob, start: u64, len: u64) -> Result<bool> {
    let mut buffer = vec![0; 1 << 20]; let mut at = 0;
    while at < len {
        let count = buffer.len().min((len - at) as usize); source.read_exact_at(start + at, &mut buffer[..count])?;
        if buffer[..count].iter().any(|&byte| byte != 0) { return Ok(true) }
        at += count as u64;
    }
    Ok(false)
}

impl Input {
    fn open(source: &dyn ImageSource, config: &Config) -> Result<Self> {
        let raw = source.image(&config.android.super_image)?;
        let mut metadata_bytes = vec![0; lp::PROBE_BYTES]; raw.read_exact_at(0, &mut metadata_bytes)?;
        let size = lp::metadata_bytes(&metadata_bytes)?; metadata_bytes.resize(size as usize, 0);
        raw.read_exact_at(lp::PROBE_BYTES as u64, &mut metadata_bytes[lp::PROBE_BYTES..])?;
        let metadata = lp::parse(&metadata_bytes).context("parsing super metadata")?;
        Ok(Self { metadata_bytes, metadata, raw })
    }

    fn image(&self, plan: &lp::Plan) -> Result<Blob> {
        Ok(blob::Concat::blob(plan.segments().iter().map(|segment| {
            segment.physical.map_or_else(|| Ok(blob::zeroes(segment.size)), |physical| blob::region(self.raw.clone(), physical, segment.size))
        }).collect::<std::io::Result<Vec<_>>>()?)?)
    }
}

pub(super) fn logical_sources(source: &dyn ImageSource, config: &Config) -> Result<BTreeMap<String, (Blob, u64)>> {
    let input = Input::open(source, config)?;
    input.metadata.plans(None)?.into_iter().map(|plan| {
        let size = plan.size;
        let name = plan.output_name.clone();
        Ok((name, (input.image(&plan)?, size)))
    }).collect()
}

pub(super) fn super_device_size(source: &dyn ImageSource, config: &Config) -> Result<u64> {
    Ok(Input::open(source, config)?.metadata.device_size())
}

fn leaf(image: &Blob, rule: &ImageRule) -> Result<avb::Descriptor> {
    let tag = match rule.avb { AvbKind::Hash => 2, AvbKind::Hashtree => 1, _ => bail!("{} has no logical AVB rule", rule.partition) };
    let parsed = avb::parse(image.clone())?;
    let found = parsed.descriptors.iter().filter(|item| item.tag() == tag)
        .filter_map(|item| item.name().ok().filter(|name| name.as_deref() == Some(&rule.partition)).map(|_| item.clone()))
        .collect::<Vec<_>>();
    if found.len() != 1 { bail!("expected one signed descriptor for {}", rule.partition) }
    Ok(found[0].clone())
}

pub(super) fn update_super(config: &Config, source: &dyn ImageSource, stock: &Stock, keys: &Keys,
                           replacements: &BTreeMap<String, Blob>) -> Result<UpdatedSuper> {
    let input = Input::open(source, config)?;
    let plans = input.metadata.plans(None)?;
    let mut by_partition = BTreeMap::new();
    for (name, rule) in &config.android.logical_rules {
        if by_partition.insert(rule.partition.as_str(), (name, rule)).is_some() { bail!("duplicate logical partition {}", rule.partition) }
    }
    let mut used = BTreeSet::new(); let mut images = BTreeMap::new(); let mut descriptors = BTreeMap::new();
    for plan in &plans {
        let original = input.image(plan)?;
        let Some((name, rule)) = by_partition.get(plan.output_name.as_str()).copied() else {
            if replacements.keys().any(|name| name == &plan.output_name) { bail!("logical replacement has no rule: {}", plan.output_name) }
            images.insert(plan.output_name.clone(), original); continue
        };
        let image = replacements.get(name).cloned().unwrap_or(original);
        if image.len()? != plan.size { bail!("{name} size differs from super plan") }
        let descriptor = leaf(&image, rule).with_context(|| format!("validating {name}"))?;
        descriptors.insert(name.clone(), descriptor);
        if replacements.contains_key(name) { used.insert(name.clone()); }
        images.insert(plan.output_name.clone(), image.clone());
    }
    if used.len() != replacements.len() {
        let missing = replacements.keys().filter(|name| !used.contains(*name)).collect::<Vec<_>>();
        bail!("logical replacements are absent from super: {missing:?}")
    }
    for (name, rule) in &config.android.logical_rules {
        if !plans.iter().any(|plan| plan.output_name == rule.partition) && !rule.optional { bail!("super has no configured logical partition for {name}") }
    }
    let prefix = blob::bytes(input.metadata_bytes);
    let mut overlays = vec![(0, prefix.clone())];
    for plan in &plans {
        let image = &images[&plan.output_name];
        for segment in plan.segments() {
            if let Some(at) = segment.physical {
                overlays.push((at, blob::region(image.clone(), segment.logical, segment.size)?));
            } else if nonzero(image, segment.logical, segment.size)? { bail!("{} has data in a zero extent", plan.output_name) }
        }
    }
    let record = stock.image(&config.android.super_image)?;
    if record.partition() != config.android.image_rules[&config.android.super_image].partition
        || record.capacity() != input.metadata.device_size() { bail!("super stock geometry mismatch") }
    let mut seed = vec![0; 4096]; prefix.read_exact_at(0, &mut seed)?;
    let mut template = codesigner::Template::from_sparse_seed(&seed)?;
    let alternate = record.codesigner().map(|value| value.firmware());
    if !firmware(stock.firmware(), alternate, &template.firmware_version()?)
        || template.rollback()? != stock.rollback() { bail!("super CodeSigner identity differs from stock") }
    template = match config.android.image_rules[&config.android.super_image].key {
        KeyPolicy::Auto => template, KeyPolicy::Tee => template.with_key_type(0)?, KeyPolicy::Ree => template.with_key_type(1)?,
    };
    seed = template.sparse_seed(4096)?;
    let raw = blob::overlay(blob::zeroes(input.metadata.device_size()), overlays)?;
    let image = codesigner::sign_sparse(sparse::encode(raw, 4096)?, &seed, &config.android.super_image, keys)?;
    let mut logical = BTreeMap::new();
    for (name, rule) in &config.android.logical_rules {
        if rule.optional && !images.contains_key(&rule.partition) { continue }
        let image = images[&rule.partition].clone();
        logical.insert(name.clone(), (image, descriptors.remove(name).context("logical descriptor disappeared")?));
    }
    Ok(UpdatedSuper { image, logical })
}

fn logical(config: &Config, stock: Blob, name: &str, keys: &Keys) -> Result<(Blob, avb::Descriptor)> {
    let template = avb::parse(stock.clone()).with_context(|| format!("parsing AVB in {name}.img"))?;
    let (_, integrity) = template.descriptors.iter().enumerate().find(|(_, descriptor)| matches!(descriptor.tag(), 1 | 2))
        .context("logical partition has no AVB integrity descriptor")?;
    let rule = config.android.logical_rules.values().find(|rule| rule.partition == name).with_context(|| format!("no logical rule for {name}"))?;
    let rules = rule.filesystem.as_ref();
    let changes_data = rules.is_some_and(|rules| rules.discover_firmware || !rules.sign_firmware.is_empty() || !rules.remove.is_empty());
    if !changes_data { return avb::resign_metadata(&template, keys) }

    let mut payload = blob::region(stock.clone(), 0, data_size(integrity)?)?;
    if let Some(rules) = rules {
        eprintln!("Processing {name} for firmware files");
        if rules.discover_firmware && f2fs::present(&payload)? {
            if !rules.preserve_stock.is_empty() || !rules.sign_firmware.is_empty() || !rules.remove.is_empty() {
                bail!("{name}: explicit file edits are unsupported on the F2FS discovery path")
            }
            (payload, _) = f2fs::resign(payload, keys, name)?;
        } else {
        for path in &rules.preserve_stock {
            let data = erofs::read(stock.clone(), path).with_context(|| format!("reading stock {name}:/{path}"))?;
            payload = erofs::replace(payload, path, &data).with_context(|| format!("preserving stock {name}:/{path}"))?;
        }
        for path in &rules.remove {
            payload = erofs::remove(payload, path).with_context(|| format!("removing {name}:/{path}"))?;
        }
        let mut firmware = rules.sign_firmware.iter().cloned().collect::<BTreeSet<_>>();
        let detected = if rules.discover_firmware {
            let files = erofs::signed_firmware(payload.clone()).with_context(|| format!("discovering signed firmware in {name}"))?;
            firmware.extend(files.iter().map(|file| file.path.clone())); files
        } else { Vec::new() };
        for path in &firmware {
            let mut data = erofs::read(payload.clone(), path).with_context(|| format!("reading {name}:/{path}"))?;
            let original = data.clone();
            let ranges = codesigner::sign_firmware(&mut data, keys, &format!("/{name}/{path}"))?;
            for range in ranges.iter().filter(|range| range.key_type == 2) {
                if data[range.start..range.end] != original[range.start..range.end] {
                    bail!("{name}:{path}: type 2 firmware changed")
                }
            }
            payload = erofs::replace(payload, path, &data).with_context(|| format!("COW signing {name}:/{path}"))?;
            for range in ranges.iter().filter(|range| range.key_type <= 1) {
                eprintln!("CodeSigned {name}:{path} ({})", if range.key_type == 0 { "TEE" } else { "REE" });
            }
        }
        if rules.discover_firmware {
            let after = erofs::signed_firmware(payload.clone()).with_context(|| format!("verifying signed firmware in rebuilt {name}"))?;
            if after.len() != detected.len() || detected.iter().zip(&after).any(|(old, new)| {
                old.path != new.path || codesigner::runtime_layout(&old.ranges, keys) != new.ranges
            }) { bail!("{name}: signed firmware set changed during rebuild: before={detected:?}, after={after:?}") }
            for file in &after {
                let data = erofs::read(payload.clone(), &file.path)?;
                if codesigner::verify_firmware(&data, keys, &format!("/{name}/{}", file.path))? != file.ranges {
                    bail!("{name}: CodeSigner verification changed ranges for {}", file.path)
                }
            }
        }
        }
    }
    avb::add_footer(payload, &template, keys)
}

fn super_image(config: &Config, source: &dyn ImageSource, keys: &Keys, catalog: Option<&Catalog>, build_id: &str) -> Result<SuperBuilt> {
    let input = Input::open(source, config)?;
    let plans = input.metadata.plans(None)?;
    if plans.is_empty() { bail!("super metadata contains no logical partitions") }
    let mut images = BTreeMap::new(); let mut descriptors = BTreeMap::new();
    for plan in &plans {
        let (image, descriptor) = logical(config, input.image(plan)?, &plan.output_name, keys)
            .with_context(|| format!("processing logical partition {}", plan.output_name))?;
        if image.len()? != plan.size { bail!("rebuilt logical partition {} changed size: {} != {}", plan.output_name, image.len()?, plan.size) }
        let name = descriptor.name()?.context("AVB integrity descriptor has no partition name")?;
        if descriptors.insert(name.clone(), descriptor).is_some() { bail!("duplicate signed AVB descriptor {name}") }
        images.insert(plan.output_name.clone(), image);
    }
    let prefix = blob::bytes(input.metadata_bytes);
    let mut overlays = vec![(0, prefix.clone())];
    for plan in &plans {
        let image = &images[&plan.output_name];
        for segment in plan.segments() {
            if let Some(physical) = segment.physical {
                overlays.push((physical, blob::region(image.clone(), segment.logical, segment.size)?));
            } else if nonzero(image, segment.logical, segment.size)? { bail!("logical partition {} has non-zero data in a zero LP extent", plan.output_name) }
        }
    }
    let raw = blob::overlay(blob::zeroes(input.metadata.device_size()), overlays)?;
    let sparse = sparse::encode(raw, 4096)?;
    let mut signer = vec![0; 4096]; prefix.read_exact_at(0, &mut signer)?;
    if codesigner::sparse_template(&blob::bytes(signer.clone())).is_err() {
        let cat = catalog.context("unsigned super requires --bl for verified sparse CodeSigner data")?;
        signer = cat.sparse_seed(config.android.st2_key_type, 4096)?;
    }
    let template = codesigner::Template::from_sparse_seed(&signer)?;
    let signer_id = template.firmware_version()?;
    if !firmware(build_id, catalog.map(Catalog::version), &signer_id) {
        bail!("{} build ID mismatch: {signer_id} is not in {build_id}", config.android.super_image)
    }
    let super_image = codesigner::sign_sparse(sparse, &signer, &config.android.super_image, keys)?;
    eprintln!("CodeSigned {} ({})", config.android.super_image, mode(template.key_type()?));
    Ok(SuperBuilt { image: super_image, descriptors })
}

fn physical(source: &dyn ImageSource, name: &str, rule: &ImageRule, keys: &Keys,
            catalog: Option<&Catalog>, build_id: &str) -> Result<(Blob, Option<avb::Descriptor>)> {
    let stock = source.image(name)?;
    if rule.codesigner == CodeSignerKind::Sparse {
        let raw = sparse::decode_if_sparse(stock).with_context(|| format!("reading raw/sparse {name}"))?;
        let signer = codesigner::sparse_template(&raw).with_context(|| format!("reading sparse CodeSigner data from {name}"))?;
        let signer_id = codesigner::Template::from_sparse_seed(&signer)?.firmware_version()?;
        if !firmware(build_id, catalog.map(Catalog::version), &signer_id) {
            bail!("{name} build ID mismatch: {signer_id} is not in the AP/BL family")
        }
        let (raw, descriptor) = if matches!(rule.avb, AvbKind::Hash | AvbKind::Hashtree) {
            let parsed = avb::parse(raw.clone())?;
            let (raw, descriptor) = avb::resign_metadata(&parsed, keys)?;
            (raw, Some(descriptor))
        } else { (raw, None) };
        let image = codesigner::sign_sparse(sparse::encode(raw, 4096)?, &signer, name, keys)?;
        eprintln!("CodeSigned {name} ({})", mode(codesigner::Template::from_sparse_seed(&signer)?.key_type()?));
        return Ok((image, descriptor))
    }
    if rule.codesigner != CodeSignerKind::Normal { bail!("{name}: physical image requires normal or sparse CodeSigner") }
    let has_avb = matches!(rule.avb, AvbKind::Hash | AvbKind::Hashtree);
    let template = has_avb.then(|| avb::parse(stock.clone())).transpose()?;
    let boundary = template.as_ref().and_then(|template| template.footer.as_ref()).map_or(stock.len()?, |footer| footer.original_size);
    if template.as_ref().is_some_and(|item| item.footer.is_none()) { bail!("required AVB footer is missing from {name}") }
    let code = codesigner::extract(&stock, boundary)?; let payload_size = boundary.checked_sub(codesigner::NORMAL as u64).context("CodeSigner boundary underflow")?;
    let image_id = code.firmware_version()?;
    let valid = if rule.partition == "modem" { codesigner::same_model(build_id, &image_id) }
        else { firmware(build_id, catalog.map(Catalog::version), &image_id) };
    if !valid {
        if rule.partition == "modem" { bail!("{name} model mismatch: {image_id} is not for {build_id}") }
        bail!("{name} build ID mismatch: {image_id} is not in the AP/BL family")
    }
    let mut payload = blob::region(stock, 0, payload_size)?;
    if let Some(ramdisk) = &rule.ramdisk {
        eprintln!("Processing {name} for firmware files");
        payload = boot::repack(payload, ramdisk, keys, name)?;
    }
    let signed = codesigner::append(payload, &code, name, keys)?;
    eprintln!("CodeSigned {name} ({})", mode(code.key_type()?));
    if let Some(template) = template { let (image, descriptor) = avb::add_footer(signed, &template, keys)?; Ok((image, Some(descriptor))) }
    else { Ok((signed, None)) }
}

fn vbmeta(input: &dyn ImageSource, name: &str, replacements: &BTreeMap<String, avb::Descriptor>, targets: &BTreeSet<String>,
          managed: &BTreeSet<String>, keys: &Keys, catalog: Option<&Catalog>, main: bool, build_id: &str) -> Result<Blob> {
    let source = if main { catalog.and_then(Catalog::vbmeta).unwrap_or(input.image(name)?) } else { input.image(name)? };
    let size = source.len()?; let code = codesigner::extract(&source, size)?;
    let image_id = code.firmware_version()?;
    if !firmware(build_id, catalog.map(Catalog::version), &image_id) {
        bail!("{name} build ID mismatch: {image_id} is not in the AP/BL family")
    }
    let parsed = avb::parse(source)?;
    let encoded = avb::standalone(&parsed, replacements, targets, managed, keys)?;
    let image = codesigner::append_vbmeta(encoded, &code, name, keys)?;
    eprintln!("CodeSigned {name} ({})", mode(code.key_type()?));
    Ok(image)
}

pub(super) fn build(config: &Config, input: &dyn ImageSource, keys: &Keys, bl: Option<&Path>) -> Result<Built> {
    let catalog = bl.map(Catalog::open).transpose()?;
    let main_vbmeta = config.android.vbmeta.last().context("no main vbmeta image is configured")?;
    let main_source = input.image(main_vbmeta)?;
    let build_id = codesigner::extract(&main_source, main_source.len()?)?.firmware_version()?;
    if let Some(catalog) = &catalog {
        catalog.require_firmware_key(keys)?;
        if !codesigner::same_model(&build_id, catalog.version()) {
            bail!("BL/AP firmware mismatch: BL {}, AP {build_id}", catalog.version())
        }
    }
    let built_super = super_image(config, input, keys, catalog.as_ref(), &build_id)?; let mut descriptors = built_super.descriptors; let mut images = BTreeMap::new();
    images.insert(config.android.super_image.clone(), built_super.image);
    for name in config.android.archive.iter().filter(|name| *name != &config.android.super_image) {
        let rule = config.android.image_rules.get(name).with_context(|| format!("missing image rule for {name}"))?;
        let (image, descriptor) = physical(input, name, rule, keys, catalog.as_ref(), &build_id)
            .with_context(|| format!("processing physical image {name}"))?;
        if let Some(descriptor) = descriptor { let partition = descriptor.name()?.context("physical AVB descriptor has no partition name")?; if descriptors.insert(partition.clone(), descriptor).is_some() { bail!("duplicate signed descriptor {partition}") } }
        images.insert(name.clone(), image);
    }
    let managed = config.android.image_rules.values().chain(config.android.logical_rules.values()).map(|rule| rule.partition.clone()).collect::<BTreeSet<_>>();
    for name in &config.android.vbmeta {
        let main = name == main_vbmeta;
        let mut targets = BTreeSet::new();
        for dep in config.android.dependencies.get(name).into_iter().flatten() {
            let rule = config.android.image_rules.get(dep).or_else(|| config.android.logical_rules.get(dep)).with_context(|| format!("dependency {dep} has no rule"))?;
            if descriptors.contains_key(&rule.partition) { targets.insert(rule.partition.clone()); }
            else if !rule.optional && matches!(rule.avb, AvbKind::Hash | AvbKind::Hashtree) { bail!("missing descriptor for {dep}") }
        }
        images.insert(name.clone(), vbmeta(input, name, &descriptors, &targets, &managed, keys, catalog.as_ref(), main, &build_id).with_context(|| format!("building {name}"))?);
    }
    Ok(Built { images, descriptors })
}
