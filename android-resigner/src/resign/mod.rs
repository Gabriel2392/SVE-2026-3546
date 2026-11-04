mod archive;
mod android;
mod avb;
mod blob;
mod boot;
mod codesigner;
mod config;
mod crypto;
mod erofs;
mod f2fs;
mod fec;
mod graph;
mod independent;
mod incremental;
mod input;
mod stock;
mod publish;
mod ramdisk;
mod sparse;
mod templates;
mod vbmeta_build;

use std::{collections::{BTreeMap, BTreeSet}, env, fs::{self, File}, path::{Path, PathBuf}};

use anyhow::{bail, Context, Result};

use crate::io::Window;
use archive::TarMd5;
use config::Config;
use crypto::Keys;
use input::StockInput;
use stock::{CodeSignerRecord, Stock, SourceHashes, sha256_bytes};
use templates::Catalog;

#[derive(Debug)]
pub struct RunOptions {
    pub ap: PathBuf,
    pub cp: PathBuf,
    pub csc: PathBuf,
    pub bl: Option<PathBuf>,
    pub bl_output: Option<PathBuf>,
    pub images: BTreeMap<String, PathBuf>,
    pub logical: BTreeMap<String, PathBuf>,
    pub super_image: Option<PathBuf>,
    pub output: PathBuf,
    pub root: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug)]
pub struct SignImageOptions {
    pub source: PathBuf,
    pub name: String,
    pub input: PathBuf,
    pub output: PathBuf,
    pub root: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug)]
pub struct BuildVbmetaOptions {
    pub source: PathBuf,
    pub images: BTreeMap<String, PathBuf>,
    pub output: PathBuf,
    pub root: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug)]
pub struct UpdateApOptions {
    pub base: PathBuf,
    pub bl: Option<PathBuf>,
    pub bl_output: Option<PathBuf>,
    pub images: BTreeMap<String, PathBuf>,
    pub logical: BTreeMap<String, PathBuf>,
    pub incremental: bool,
    pub output: PathBuf,
    pub root: Option<PathBuf>,
    pub force: bool,
}

fn derive_stock(cfg_raw: &[u8], cfg: &Config, src: &StockInput, bl: &Path,
                hashes: SourceHashes, generated: bool) -> Result<Stock> {
    let main = cfg.android.vbmeta.last().context("vbmeta.img is not configured")?;
    let img = src.image(main)?;
    let code = codesigner::extract(&img, img.len()?)?;
    let fw = code.firmware_version()?;
    let rb = code.rollback()?;
    let cat = Catalog::open(bl)?;
    if fw != cat.version() || rb != cat.normal(cfg.android.st2_key_type)?.rollback()? { bail!("BL and AP firmware do not match") }
    let mut stock = Stock::new(&cfg.soc, &fw, rb, sha256_bytes(cfg_raw), hashes)?;
    for (name, rule) in &cfg.android.image_rules {
        let mut rec = independent::record_from_stock(name, src.image(name)?, rule, None)?;
        let key = match rule.key {
            config::KeyPolicy::Auto => cfg.android.st2_key_type,
            config::KeyPolicy::Tee => 0,
            config::KeyPolicy::Ree => 1,
        };
        rec = match rule.codesigner {
            config::CodeSignerKind::Normal | config::CodeSignerKind::StandaloneVbmeta => {
                rec.with_codesigner(CodeSignerRecord::normal(cat.normal(key)?)?)
            }
            config::CodeSignerKind::Sparse => {
                rec.with_codesigner(CodeSignerRecord::sparse(&cat.sparse_seed(key, 4096)?)?)
            }
            config::CodeSignerKind::None => rec,
        };
        if generated && rule.avb != config::AvbKind::Standalone { rec = rec.generated(); }
        stock.insert_image(name, rec)?;
    }
    let logical = android::logical_sources(src, cfg)?;
    for (name, rule) in &cfg.android.logical_rules {
        let Some((img, size)) = logical.get(&rule.partition) else {
            if rule.optional { continue }
            bail!("super has no logical partition {}", rule.partition)
        };
        let mut rec = independent::record_from_stock(name, img.clone(), rule, Some(*size))?;
        if generated { rec = rec.generated(); }
        stock.insert_logical(name, rec)?;
    }
    Ok(stock)
}

pub fn sign_image(o: SignImageOptions) -> Result<PathBuf> {
    let root = project_root(o.root.as_deref())?;
    let cfg_raw = fs::read(root.join("s5e8825.json"))?;
    let cfg = Config::load_path(&root.join("s5e8825.json"))?;
    cfg.validate_image_rules()?;
    let p = Stock::from_archive(&o.source)?.context("archive has no android-resigner.json")?;
    p.require_config(&cfg_raw)?;
    if p.soc() != cfg.soc { bail!("saved signing data uses a different SoC") }
    let rule = cfg.android.image_rules.get(&o.name).or_else(|| cfg.android.logical_rules.get(&o.name))
        .with_context(|| format!("no signing rule for {}", o.name))?;
    let src = blob::file(&o.input)?;
    eprintln!("Signing {}", o.name);
    let built = independent::sign(&o.name, src, &p, rule, &Keys::load(&root, &cfg.signing)?, &cfg.android.avb_generation)?;
    let key = built.metadata.code_key;
    write_blob(built.image, &o.input, &o.output, o.force)?;
    if let Some(key) = key { eprintln!("CodeSigned {} ({})", o.name, if key == 0 { "TEE" } else { "REE" }); }
    Ok(o.output)
}

pub fn build_vbmeta(o: BuildVbmetaOptions) -> Result<PathBuf> {
    let root = project_root(o.root.as_deref())?;
    let raw = fs::read(root.join("s5e8825.json"))?;
    let cfg = Config::load_path(&root.join("s5e8825.json"))?;
    cfg.validate_image_rules()?;
    let p = Stock::from_archive(&o.source)?.context("archive has no android-resigner.json")?;
    p.require_config(&raw)?;
    if p.soc() != cfg.soc { bail!("saved signing data uses a different SoC") }
    let keys = Keys::load(&root, &cfg.signing)?;
    let mut src = BTreeMap::new();
    for (name, path) in &o.images {
        if !path.is_file() { bail!("input image does not exist: {}", path.display()) }
        let image = blob::file(path)?;
        src.insert(name.clone(), vbmeta_build::Image { image, descriptor: None });
    }
    let built = vbmeta_build::build(&cfg, &p, &keys, &src)?;
    if built.descriptors.is_empty() { bail!("no AVB descriptors were built") }
    if o.output.exists() && !o.force { bail!("output already exists: {}", o.output.display()) }
    let parent = output_parent(&o.output);
    fs::create_dir_all(parent)?;
    let name = o.output.file_name().and_then(|name| name.to_str()).context("vbmeta output has no filename")?;
    let temp = parent.join(format!(".{name}.partial.{}", std::process::id()));
    if temp.exists() { fs::remove_dir_all(&temp)? }
    fs::create_dir(&temp)?;
    let result = (|| -> Result<()> {
        for (name, image) in built.images { write_out(image, &temp.join(name), false)?; }
        if !o.output.exists() { fs::rename(&temp, &o.output)?; return Ok(()) }
        let backup = parent.join(format!(".{name}.backup.{}", std::process::id()));
        if backup.exists() { fs::remove_dir_all(&backup)? }
        fs::rename(&o.output, &backup)?;
        if let Err(error) = fs::rename(&temp, &o.output) {
            fs::rename(&backup, &o.output)?;
            return Err(error.into())
        }
        fs::remove_dir_all(backup)?;
        Ok(())
    })();
    if result.is_err() && temp.exists() { let _ = fs::remove_dir_all(&temp); }
    result?;
    Ok(o.output)
}

fn image_name(rules: &BTreeMap<String, config::ImageRule>, value: &str) -> Result<String> {
    if rules.contains_key(value) { return Ok(value.to_owned()) }
    let found = rules.iter().filter_map(|(name, rule)| (rule.partition == value).then_some(name)).collect::<Vec<_>>();
    if found.len() != 1 { bail!("unknown or ambiguous image name: {value}") }
    Ok(found[0].clone())
}

fn inputs(paths: BTreeMap<String, PathBuf>, rules: &BTreeMap<String, config::ImageRule>) -> Result<BTreeMap<String, blob::Blob>> {
    let mut out = BTreeMap::new();
    for (value, path) in paths {
        let name = image_name(rules, &value)?;
        if out.contains_key(&name) { bail!("image was supplied twice: {name}") }
        if !path.is_file() { bail!("image does not exist: {}", path.display()) }
        out.insert(name, blob::file(&path)?);
    }
    Ok(out)
}

pub fn update_ap(o: UpdateApOptions) -> Result<PathBuf> {
    let root = project_root(o.root.as_deref())?;
    let raw = fs::read(root.join("s5e8825.json"))?;
    let cfg = Config::load_path(&root.join("s5e8825.json"))?;
    cfg.validate_image_rules()?;
    let names = cfg.android.archive.iter().chain(&cfg.android.vbmeta).cloned().collect::<Vec<_>>();
    let mut base = StockInput::single(&o.base, names)?;
    let stock = if let Some(stock) = Stock::from_archive(&o.base)? {
        stock
    } else {
        let bl = o.bl.as_deref().context("archive has no android-resigner.json; pass --bl once")?;
        let hashes = SourceHashes::from_unified(bl, &o.base)?;
        derive_stock(&raw, &cfg, &base, bl, hashes, true)?
    };
    stock.require_config(&raw)?;
    if stock.soc() != cfg.soc { bail!("saved signing data uses a different SoC") }
    if let Some(bl) = &o.bl {
        let cat = Catalog::open(bl)?;
        if cat.version() != stock.firmware() || cat.normal(cfg.android.st2_key_type)?.rollback()? != stock.rollback() {
            bail!("BL and AP firmware do not match")
        }
    }
    let keys = Keys::load(&root, &cfg.signing)?;
    let physical = inputs(o.images, &cfg.android.image_rules)?;
    let logical = inputs(o.logical, &cfg.android.logical_rules)?;
    if physical.is_empty() && logical.is_empty() { bail!("update-ap requires at least one replacement") }
    let super_name = &cfg.android.super_image;
    if !logical.is_empty() && physical.contains_key(super_name) { bail!("super and logical replacements cannot be combined") }
    for name in physical.keys() {
        if cfg.android.image_rules[name].codesigner == config::CodeSignerKind::StandaloneVbmeta {
            bail!("standalone vbmeta is regenerated and cannot be supplied: {name}")
        }
    }
    let mut signed_physical = BTreeMap::new();
    for (name, image) in physical {
        let rule = &cfg.android.image_rules[&name];
        let built = independent::sign(&name, image, &stock, rule, &keys, &cfg.android.avb_generation)?;
        if let Some(key) = built.metadata.code_key {
            eprintln!("CodeSigned {name} ({})", if key == 0 { "TEE" } else { "REE" });
        }
        signed_physical.insert(name, built.image);
    }
    let mut signed_logical = BTreeMap::new();
    for (name, image) in logical {
        let rule = &cfg.android.logical_rules[&name];
        let built = independent::sign(&name, image, &stock, rule, &keys, &cfg.android.avb_generation)?;
        signed_logical.insert(name, built.image);
    }
    if let Some(image) = signed_physical.get(super_name) { base.replace(super_name, image.clone())? }
    let mut changed = signed_physical.clone();
    let mut sources = android::logical_sources(&base, &cfg)?;
    let mut leaves = BTreeMap::new();
    if !signed_logical.is_empty() {
        let updated = android::update_super(&cfg, &base, &stock, &keys, &signed_logical)?;
        changed.insert(super_name.clone(), updated.image.clone());
        sources.clear();
        for (name, (image, descriptor)) in updated.logical {
            let part = cfg.android.logical_rules[&name].partition.clone();
            sources.insert(part, (image.clone(), image.len()?));
            leaves.insert(name, vbmeta_build::Image { image, descriptor: Some(descriptor) });
        }
    }
    let mut inputs = BTreeMap::new();
    for (name, rule) in &cfg.android.image_rules {
        if rule.codesigner == config::CodeSignerKind::StandaloneVbmeta { continue }
        let image = if name == super_name { changed.get(name).cloned().unwrap_or(base.transport(name)?) }
            else { signed_physical.get(name).cloned().unwrap_or(base.transport(name)?) };
        inputs.insert(name.clone(), vbmeta_build::Image { image, descriptor: None });
    }
    for (name, rule) in &cfg.android.logical_rules {
        if let Some(value) = leaves.remove(name) { inputs.insert(name.clone(), value); continue }
        let Some((image, _)) = sources.get(&rule.partition) else {
            if rule.optional { continue }
            bail!("base super has no logical partition {}", rule.partition)
        };
        inputs.insert(name.clone(), vbmeta_build::Image { image: image.clone(), descriptor: None });
    }
    let built = vbmeta_build::build(&cfg, &stock, &keys, &inputs)?;
    let dependencies = built.images;
    let mut rebuilt = changed;
    for (name, image) in dependencies {
        if rebuilt.insert(name.clone(), image).is_some() { bail!("rebuilt image appears twice: {name}") }
    }
    let mut archives = vec![publish::Archive {
        base: o.base, output: o.output, incremental: o.incremental, force: o.force,
        plain: Some((stock::MEMBER.to_owned(), stock.encode()?)),
    }];
    if let Some(base) = o.bl {
        archives.push(publish::Archive {
            base, output: o.bl_output.context("BL output path is missing")?, incremental: false, force: o.force,
            plain: None,
        });
    } else if o.bl_output.is_some() { bail!("BL output requires a BL input") }
    let result = publish::publish(publish::Options { archives, images: rebuilt })?;
    let ap = result.archives.first().context("AP was not written")?.path.clone();
    for (index, archive) in result.archives.iter().enumerate() {
        let file = archive.path.file_name().and_then(|name| name.to_str()).unwrap_or("output");
        if index == 0 && o.incremental { println!("Built {file} with these images:") }
        else { println!("Updated {file} with these new images:") }
        for name in &archive.members { println!("  {name}") }
    }
    Ok(ap)
}

fn write_blob(src: blob::Blob, input: &Path, out: &Path, force: bool) -> Result<()> {
    if !input.is_file() { bail!("input image does not exist: {}", input.display()) }
    if input.canonicalize().ok() == out.canonicalize().ok() { bail!("output must not overwrite input") }
    write_out(src, out, force)
}

fn write_out(src: blob::Blob, out: &Path, force: bool) -> Result<()> {
    if out.exists() && !force { bail!("output already exists: {}", out.display()) }
    fs::create_dir_all(output_parent(out))?;
    let tmp = Partial::create(out)?;
    let len = src.len()?;
    let mut r = Window::new(src, 0, len)?;
    let mut f = File::create(&tmp.path)?;
    std::io::copy(&mut r, &mut f)?;
    f.sync_all()?;
    tmp.publish(out)
}

struct Partial { path: PathBuf, published: bool }

impl Partial {
    fn create(output: &Path) -> Result<Self> {
        let parent = output_parent(output);
        let name = output.file_name().and_then(|name| name.to_str()).context("output filename is not UTF-8")?;
        for attempt in 0..100u32 {
            let path = parent.join(format!(".{name}.partial.{}.{}", std::process::id(), attempt));
            if !path.exists() { return Ok(Self { path, published: false }) }
        }
        bail!("could not allocate a unique partial archive beside {}", output.display())
    }

    fn publish(mut self, output: &Path) -> Result<()> {
        fs::rename(&self.path, output).with_context(|| format!("writing {}", output.display()))?;
        self.published = true; Ok(())
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.published { let _ = fs::remove_file(&self.path); }
    }
}

fn backup(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() { return Ok(None) }
    let parent = output_parent(path);
    let name = path.file_name().and_then(|name| name.to_str()).context("backup filename is not UTF-8")?;
    for attempt in 0..100u32 {
        let copy = parent.join(format!(".{name}.rollback.{}.{}", std::process::id(), attempt));
        if copy.exists() { continue }
        fs::hard_link(path, &copy)?;
        return Ok(Some(copy))
    }
    bail!("could not allocate a backup beside {}", path.display())
}

fn restore(path: &Path, copy: Option<&Path>) {
    if let Some(copy) = copy {
        let _ = fs::remove_file(path);
        let _ = fs::rename(copy, path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn project_root(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let root = path.canonicalize().with_context(|| format!("locating project root {}", path.display()))?;
        if !root.join("s5e8825.json").is_file() { bail!("{} has no s5e8825.json", root.display()) }
        return Ok(root)
    }

    let mut starts = vec![env::current_dir().context("locating current directory")?];
    if let Ok(executable) = env::current_exe() {
        if let Some(parent) = executable.parent() { starts.push(parent.to_owned()) }
    }
    for start in starts {
        for candidate in start.ancestors() {
            if candidate.join("s5e8825.json").is_file() && candidate.join("signer/keys").is_dir() {
                return candidate.canonicalize().with_context(|| format!("locating project root {}", candidate.display()))
            }
        }
    }
    bail!("could not find s5e8825.json and signer/keys; use --root")
}

fn output_parent(output: &Path) -> &Path {
    output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn validate_streaming(config: &Config, input: &StockInput) -> Result<()> {
    if config.signing.codesigner_type != 4 { bail!("only CodeSigner V5/ECDSA is supported") }
    if config.android.avb_algorithm != "SHA256_RSA4096" { bail!("unsupported AVB algorithm {}", config.android.avb_algorithm) }
    if config.android.st2_key_type > 1 { bail!("invalid Android ST2 key type") }
    config.validate_image_rules()?;
    if !config.android.archive.contains(&config.android.super_image) { bail!("configured super image is not in the Android archive") }
    let wanted = config.android.archive.iter().chain(&config.android.vbmeta).map(String::as_str).collect::<BTreeSet<_>>();
    let actual = input.names().collect::<BTreeSet<_>>();
    if wanted != actual { bail!("firmware images do not match s5e8825.json") }
    Ok(())
}

pub fn run(options: RunOptions) -> Result<PathBuf> {
    let root = project_root(options.root.as_deref())?;
    let cfg_path = root.join("s5e8825.json");
    let cfg_raw = fs::read(&cfg_path)?;
    let config = Config::load_path(&cfg_path)?;
    let bl = options.bl.as_ref().context("--bl BL_RESIGNED is required")?;
    if !bl.is_file() { bail!("BL archive does not exist or is not a file: {}", bl.display()) }
    let output = if options.output.is_dir() { options.output.join("AP_RESIGNED.tar.md5") } else { options.output.clone() };
    let parent = output_parent(&output);
    fs::create_dir_all(parent).with_context(|| format!("creating output directory {}", parent.display()))?;
    if output.exists() {
        let existing = output.canonicalize().with_context(|| format!("locating existing output {}", output.display()))?;
        for input in [&options.ap, &options.cp, &options.csc]
            .into_iter()
            .chain(options.bl.iter())
            .chain(options.images.values())
            .chain(options.logical.values())
            .chain(options.super_image.iter())
        {
            if input.canonicalize().ok().as_ref() == Some(&existing) {
                bail!("refusing to overwrite input archive {}", input.display())
            }
        }
        if !options.force { bail!("output already exists: {} (use --force to replace it)", output.display()) }
    }

    let requested = config.android.archive.iter().chain(&config.android.vbmeta).cloned().collect::<Vec<_>>();
    eprintln!("Mapping firmware");
    let mut input = StockInput::open(&options.ap, &options.cp, &options.csc, requested)?;
    let keys = Keys::load(&root, &config.signing)?;
    let stock = if let Some(bl) = options.bl.as_deref() {
        let hashes = SourceHashes::from_paths(bl, &options.ap, &options.cp, &options.csc)?;
        Some(derive_stock(&cfg_raw, &config, &input, bl, hashes, true)?)
    } else {
        None
    };
    if let Some(stock) = &stock {
        stock.require_config(&cfg_raw)?;
        if stock.soc() != config.soc { bail!("saved signing data uses a different SoC") }
    }
    let mut paths = options.images;
    if let Some(path) = options.super_image {
        if paths.keys().any(|name| image_name(&config.android.image_rules, name).ok().as_deref() == Some(&config.android.super_image)) {
            bail!("super was supplied twice")
        }
        paths.insert(config.android.super_image.clone(), path);
    }
    let physical = inputs(paths, &config.android.image_rules)?;
    let logical = inputs(options.logical, &config.android.logical_rules)?;
    if !logical.is_empty() && physical.contains_key(&config.android.super_image) { bail!("super and logical replacements cannot be combined") }
    eprintln!("Signing images");
    if let Some(stock) = &stock {
        for (name, source) in physical {
            let rule = &config.android.image_rules[&name];
            if rule.codesigner == config::CodeSignerKind::StandaloneVbmeta { bail!("standalone vbmeta is regenerated: {name}") }
            let built = independent::wrap(&name, source, stock, rule, &keys, &config.android.avb_generation)?;
            if built.partition != rule.partition || matches!(rule.avb, config::AvbKind::Hash | config::AvbKind::Hashtree) && built.descriptor.is_none() { bail!("{name} has the wrong partition or AVB data after signing") }
            input.replace(&name, built.image)?;
        }
        if !logical.is_empty() {
            let mut signed = BTreeMap::new();
            for (name, source) in logical {
                let rule = &config.android.logical_rules[&name];
                let built = independent::wrap(&name, source, stock, rule, &keys, &config.android.avb_generation)?;
                if built.partition != rule.partition || built.descriptor.is_none() { bail!("{name} has the wrong partition or AVB data after signing") }
                signed.insert(name, built.image);
            }
            let updated = android::update_super(&config, &input, stock, &keys, &signed)?;
            input.replace(&config.android.super_image, updated.image)?;
        }
    }
    validate_streaming(&config, &input)?;
    let mut built = android::build(&config, &input, &keys, options.bl.as_deref())?;
    drop(built.descriptors);
    let main = config.android.vbmeta.last().context("vbmeta.img is not configured")?.clone();
    let main_image = built.images.get(&main).context("rebuilt vbmeta.img is missing")?.clone();

    let partial = Partial::create(&output)?;
    let output_name = output.file_name().and_then(|name| name.to_str()).context("output filename is not UTF-8")?;
    eprintln!("Packing {output_name}");
    let tar_name = output_name.strip_suffix(".md5").unwrap_or(output_name);
    let mut tar = TarMd5::create(&partial.path, tar_name)?;
    let data = stock.as_ref().map(Stock::encode).transpose()?
        .map(|data| (stock::MEMBER.to_owned(), blob::bytes(data)));
    input.pack(&mut tar, &mut built.images, data)?;
    tar.finish()?;
    fs::OpenOptions::new().read(true).open(&partial.path)?.sync_all()?;
    if let Some(bl) = options.bl {
        if publish::contains(&bl, &main)? {
            let bl_output = options.bl_output.unwrap_or_else(|| bl.clone());
            let bl_name = bl_output.file_name().and_then(|name| name.to_str()).unwrap_or("BL_RESIGNED.tar.md5").to_owned();
            eprintln!("Updating {bl_name}");
            let in_place = bl == bl_output
                || bl.canonicalize().ok().as_ref() == bl_output.canonicalize().ok().as_ref();
            let copy = backup(&bl_output)?;
            let updated = publish::publish(publish::Options {
                archives: vec![publish::Archive {
                    base: bl,
                    output: bl_output.clone(),
                    incremental: false,
                    force: options.force || in_place,
                    plain: None,
                }],
                images: BTreeMap::from([(main.clone(), main_image)]),
            });
            if let Err(error) = updated {
                restore(&bl_output, copy.as_deref());
                return Err(error)
            }
            if let Err(error) = incremental::parse_trailer(&bl_output) {
                restore(&bl_output, copy.as_deref());
                return Err(error)
            }
            if let Err(error) = partial.publish(&output) {
                restore(&bl_output, copy.as_deref());
                return Err(error)
            }
            if let Some(copy) = copy { fs::remove_file(copy)?; }
            println!("Updated {bl_name} with these new images:");
            println!("  {main}");
            return Ok(output)
        }
    }
    partial.publish(&output)?;
    Ok(output)
}
