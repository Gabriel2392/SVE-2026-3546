use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File}, path::{Path, PathBuf}, sync::Arc};

use anyhow::{bail, Context, Result};

use crate::{archive::TarIndex, io::ReadAt};
use super::{blob::Blob, incremental::{self, UpdateOptions}};

pub(super) struct Archive {
    pub base: PathBuf,
    pub output: PathBuf,
    pub incremental: bool,
    pub force: bool,
    pub plain: Option<(String, Vec<u8>)>,
}

pub(super) struct Options {
    pub archives: Vec<Archive>,
    pub images: BTreeMap<String, Blob>,
}

pub(super) struct ArchiveResult {
    pub path: PathBuf,
    pub members: Vec<String>,
}

pub(super) struct PublishResult {
    pub archives: Vec<ArchiveResult>,
}

fn images_in(path: &PathBuf, names: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    incremental::parse_trailer(path)?;
    let source: Arc<dyn ReadAt> = Arc::new(File::open(path)?);
    let index = TarIndex::open(source).with_context(|| format!("reading {}", path.display()))?;
    let mut found = BTreeSet::new();
    for entry in index.entries() {
        if !matches!(entry.kind, 0 | b'0') { continue }
        let name = entry.name.rsplit('/').next().unwrap_or(&entry.name);
        let Some(name) = name.strip_suffix(".lz4") else { continue };
        if names.contains(name) && !found.insert(name.to_owned()) { bail!("duplicate configured image {name:?} in {}", path.display()) }
    }
    Ok(found)
}

pub(super) fn contains(path: &Path, name: &str) -> Result<bool> {
    Ok(images_in(&path.to_path_buf(), &BTreeSet::from([name.to_owned()]))?.contains(name))
}

fn target(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    let Some(parent) = path.parent() else { return Ok(path) };
    let name = path.file_name().context("archive output has no filename")?;
    Ok(if parent.exists() { fs::canonicalize(parent)?.join(name) } else { path })
}

pub(super) fn publish(options: Options) -> Result<PublishResult> {
    if options.archives.is_empty() || options.images.is_empty() { bail!("no archives or rebuilt images were supplied") }
    let names = options.images.keys().cloned().collect::<BTreeSet<_>>();
    let bases = options.archives.iter().map(|item| fs::canonicalize(&item.base)).collect::<std::io::Result<BTreeSet<_>>>()?;
    let mut outputs = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut ready = Vec::new();
    for archive in options.archives {
        let output = target(&archive.output)?;
        let base = fs::canonicalize(&archive.base)?;
        if bases.contains(&output) && output != base { bail!("output must not replace another input archive") }
        if !outputs.insert(output) { bail!("duplicate archive output {}", archive.output.display()) }
        let found = images_in(&archive.base, &names)?;
        if found.is_empty() { bail!("{} contains none of the rebuilt images", archive.base.display()) }
        used.extend(found.iter().cloned());
        let changed = found.into_iter().map(|name| (name.clone(), options.images[&name].clone())).collect();
        let item = incremental::stage(UpdateOptions {
            base: archive.base,
            changed,
            dependencies: BTreeMap::new(),
            plain: archive.plain,
            output: archive.output,
            incremental: archive.incremental,
            force: archive.force,
        })?;
        ready.push(item);
    }
    let missing = names.difference(&used).cloned().collect::<Vec<_>>();
    if !missing.is_empty() { bail!("rebuilt images are absent from every output archive: {missing:?}") }
    let mut backups = Vec::new();
    for (index, item) in ready.iter().enumerate() {
        let output = item.output();
        if !output.exists() { continue }
        if !item.force() {
            for (_, backup) in backups { let _ = fs::remove_file(backup); }
            bail!("output already exists: {}", output.display())
        }
        let name = output.file_name().and_then(|name| name.to_str()).context("archive output has no filename")?;
        let backup = output.with_file_name(format!(".{name}.backup.{}.{}", std::process::id(), index));
        if backup.exists() {
            for (_, backup) in backups { let _ = fs::remove_file(backup); }
            bail!("archive backup already exists: {}", backup.display())
        }
        if let Err(error) = fs::hard_link(output, &backup) {
            for (_, backup) in backups { let _ = fs::remove_file(backup); }
            return Err(error.into())
        }
        backups.push((output.to_owned(), backup));
    }
    let mut archives = Vec::with_capacity(ready.len());
    for item in ready {
        match item.publish() {
            Ok(item) => archives.push(ArchiveResult { path: item.path, members: item.members }),
            Err(error) => {
                for item in &archives { let _ = fs::remove_file(&item.path); }
                for (output, backup) in backups.iter().rev() { let _ = fs::rename(backup, output); }
                return Err(error)
            }
        }
    }
    for (_, backup) in backups { fs::remove_file(backup)?; }
    Ok(PublishResult { archives })
}
