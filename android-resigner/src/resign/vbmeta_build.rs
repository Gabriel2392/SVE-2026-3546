use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};

use super::{
    avb::{self, Descriptor},
    blob::{self, Blob},
    codesigner::{self, Template},
    config::{AvbKind, CodeSignerKind, Config, ImageRule, KeyPolicy},
    crypto::Keys,
    graph::DependencyGraph,
    stock::{CodeSignerMaterial, Stock},
    sparse,
};

pub(super) struct Image {
    pub image: Blob,
    pub descriptor: Option<Descriptor>,
}

pub(super) struct Built {
    pub images: BTreeMap<String, Blob>,
    pub descriptors: BTreeMap<String, Descriptor>,
}

fn template(stock: &Stock, name: &str, rule: &ImageRule) -> Result<Template> {
    let value = stock.image(name)?.codesigner().context("stock data has no CodeSigner entry")?;
    let value = match value.material()? {
        CodeSignerMaterial::Normal(value) => value,
        CodeSignerMaterial::Sparse(value) => Template::from_sparse_seed(&value)?,
    };
    match rule.key {
        KeyPolicy::Auto => Ok(value),
        KeyPolicy::Tee => value.with_key_type(0),
        KeyPolicy::Ree => value.with_key_type(1),
    }
}

fn want(rule: &ImageRule) -> Option<u64> {
    match rule.avb {
        AvbKind::Hash => Some(2),
        AvbKind::Hashtree => Some(1),
        _ => None,
    }
}

fn pick(list: &[Descriptor], rule: &ImageRule) -> Result<Option<Descriptor>> {
    let Some(tag) = want(rule) else { return Ok(None) };
    let mut found = Vec::new();
    for item in list.iter().filter(|item| item.tag() == tag) {
        if item.name()?.as_deref() == Some(&rule.partition) { found.push(item); }
    }
    if found.len() != 1 { bail!("expected one AVB descriptor for {}", rule.partition) }
    Ok(Some(found[0].clone()))
}

fn parse(source: Blob, rule: &ImageRule) -> Result<Option<Descriptor>> {
    if want(rule).is_none() { return Ok(None) }
    let source = if rule.codesigner == CodeSignerKind::Sparse { sparse::decode_if_sparse(source)? } else { source };
    pick(&avb::parse(source)?.descriptors, rule)
}

fn desc(name: &str, rule: &ImageRule, value: Option<&Image>, stock: &Stock) -> Result<Option<Descriptor>> {
    if want(rule).is_none() { return Ok(None) }
    if let Some(value) = value {
        if let Some(item) = &value.descriptor {
            if pick(&[item.clone()], rule)?.is_some() { return Ok(Some(item.clone())) }
        }
        return parse(value.image.clone(), rule).with_context(|| format!("reading descriptor from {name}"))
    }
    let Some(value) = stock.record(name)?.avb_template() else {
        if want(rule).is_some() { bail!("stock has no AVB descriptor for {name}") }
        return Ok(None)
    };
    pick(&value.parsed()?.descriptors, rule)
}

fn build_one(name: &str, cfg: &Config, stock: &Stock, keys: &Keys,
             descriptors: &BTreeMap<String, Descriptor>) -> Result<Blob> {
    let rule = cfg.android.image_rules.get(name).context("vbmeta target has no image rule")?;
    if rule.codesigner != CodeSignerKind::StandaloneVbmeta || rule.avb != AvbKind::Standalone {
        bail!("{name} is not a standalone vbmeta target")
    }
    let record = stock.image(name)?;
    if record.partition() != rule.partition { bail!("{name} stock/config partition mismatch") }
    let parsed = record.avb_template().context("stock data has no standalone AVB image")?.parsed()?;
    if parsed.footer.is_some() { bail!("{name} stock AVB image has a footer") }
    let deps = cfg.android.dependencies.get(name).cloned().unwrap_or_default();
    let mut updates = BTreeMap::new();
    let mut targets = BTreeSet::new();
    let mut tags = BTreeMap::<String, BTreeSet<u64>>::new();
    for item in &parsed.descriptors {
        if let Some(part) = item.name()? { tags.entry(part).or_default().insert(item.tag()); }
    }
    for dep in deps {
        let rule = cfg.android.image_rules.get(&dep).or_else(|| cfg.android.logical_rules.get(&dep))
            .with_context(|| format!("dependency {dep} has no rule"))?;
        if rule.optional && !stock.has(&dep) && !descriptors.contains_key(&dep) { continue }
        let kinds = tags.get(&rule.partition).with_context(|| format!("{name} has no descriptor for required image {dep}"))?;
        targets.insert(rule.partition.clone());
        if let Some(item) = descriptors.get(&dep) {
            if kinds.contains(&item.tag()) { updates.insert(rule.partition.clone(), item.clone()); }
            else if !kinds.contains(&4) { bail!("{name} descriptor type mismatch for dependency {dep}") }
        } else if matches!(rule.avb, AvbKind::Hash | AvbKind::Hashtree) && !kinds.contains(&4) {
            bail!("{name} has no fresh descriptor for dependency {dep}")
        } else if rule.avb == AvbKind::Standalone && !kinds.contains(&4) {
            bail!("{name} cannot update non-chain standalone dependency {dep}")
        }
    }
    let raw = avb::standalone(&parsed, &updates, &targets, keys)?;
    let cap = record.capacity().checked_sub(codesigner::NORMAL as u64).context("vbmeta stock capacity is too small")?;
    if raw.len() as u64 > cap { bail!("rebuilt {name} exceeds stock capacity") }
    let len = raw.len() as u64;
    let payload = blob::Concat::blob([blob::bytes(raw), blob::zeroes(cap - len)])?;
    codesigner::append(payload, &template(stock, name, rule)?, name, keys)
}

pub(super) fn build(cfg: &Config, stock: &Stock, keys: &Keys,
                    images: &BTreeMap<String, Image>) -> Result<Built> {
    let nodes = cfg.android.image_rules.keys().cloned().chain(cfg.android.logical_rules.iter().filter_map(|(name, rule)| {
        (!rule.optional || stock.has(name) || images.contains_key(name)).then_some(name.clone())
    })).collect::<Vec<_>>();
    let active = nodes.iter().cloned().collect::<BTreeSet<_>>();
    let deps = cfg.android.dependencies.iter().filter_map(|(name, deps)| active.contains(name).then(|| {
        (name.clone(), deps.iter().filter(|dep| active.contains(*dep)).cloned().collect())
    })).collect::<BTreeMap<_, _>>();
    let graph = DependencyGraph::new(nodes.clone(), &deps)?;
    let selected = nodes.iter().cloned().collect::<BTreeSet<_>>();
    let order = graph.rebuild_order(&selected)?;
    let mut descriptors = BTreeMap::new();
    for name in &nodes {
        let rule = cfg.android.image_rules.get(name).or_else(|| cfg.android.logical_rules.get(name)).context("dependency graph contains no image rule")?;
        if let Some(value) = desc(name, rule, images.get(name), stock)? { descriptors.insert(name.clone(), value); }
    }
    let configured = cfg.android.vbmeta.iter().cloned().collect::<BTreeSet<_>>();
    let mut images = BTreeMap::new();
    for name in order {
        if !configured.contains(&name) { continue }
        let image = build_one(&name, cfg, stock, keys, &descriptors)?;
        images.insert(name.clone(), image);
    }
    if images.len() != configured.len() { bail!("dependency graph did not build every vbmeta target") }
    Ok(Built { images, descriptors })
}
