use std::{collections::BTreeMap, env, ffi::OsString, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use android_resigner::resign::{
    BuildVbmetaOptions, RunOptions, SignImageOptions, build_vbmeta, sign_image, update_ap,
    Soc, UpdateApOptions,
};

#[derive(Debug)]
struct FullArgs {
    ap: PathBuf,
    cp: PathBuf,
    csc: PathBuf,
    bl: Option<PathBuf>,
    bl_output: Option<PathBuf>,
    aosp_zip: Option<PathBuf>,
    images: BTreeMap<String, PathBuf>,
    logical: BTreeMap<String, PathBuf>,
    super_image: Option<PathBuf>,
    output: PathBuf,
    root: Option<PathBuf>,
    force: bool,
}

#[derive(Debug)]
struct SignImageArgs {
    source: PathBuf,
    name: String,
    input: PathBuf,
    output: PathBuf,
    root: Option<PathBuf>,
    force: bool,
}

#[derive(Debug)]
struct BuildVbmetaArgs {
    source: PathBuf,
    images: BTreeMap<String, PathBuf>,
    output: PathBuf,
    root: Option<PathBuf>,
    force: bool,
}

#[derive(Debug)]
struct UpdateApArgs {
    base: PathBuf,
    bl: Option<PathBuf>,
    bl_output: Option<PathBuf>,
    aosp_zip: Option<PathBuf>,
    images: BTreeMap<String, PathBuf>,
    logical: BTreeMap<String, PathBuf>,
    incremental: bool,
    output: PathBuf,
    root: Option<PathBuf>,
    force: bool,
}

#[derive(Debug)]
enum Command {
    SignImage(SignImageArgs),
    BuildVbmeta(BuildVbmetaArgs),
    UpdateAp(UpdateApArgs),
    BuildAp(FullArgs),
    Full(FullArgs),
}

fn usage(program: &OsString) -> String {
    let program = PathBuf::from(program);
    format!(
        "usage:\n  {0} --soc {{s5e8825,s5e9925}} AP CP CSC --bl BL_RESIGNED [options]\n  {0} --soc {{s5e8825,s5e9925}} update-ap --base AP_RESIGNED.tar.md5 [--bl BL_RESIGNED] [--image NAME=PATH]... [--logical NAME=PATH]... [--incremental] [-o OUTPUT]\n  {0} --soc {{s5e8825,s5e9925}} sign-image --from AP_RESIGNED.tar.md5 --name NAME INPUT OUTPUT\n  {0} --soc {{s5e8825,s5e9925}} build-vbmeta --from AP_RESIGNED.tar.md5 --image NAME=PATH... -o DIR\n\noptions: [--aosp-zip PATH] [--bl-output OUT] [--image NAME=PATH]... [--logical NAME=PATH]... [--super PATH] [-o AP_RESIGNED.tar.md5] [--root DIR] [--force]",
        program.display()
    )
}

fn value<'a>(values: &'a [OsString], at: &mut usize, option: &str, program: &OsString) -> Result<&'a OsString> {
    *at += 1;
    values.get(*at).with_context(|| format!("{option} needs a value\n{}", usage(program)))
}

fn set_path(slot: &mut Option<PathBuf>, argument: &OsString, option: &str) -> Result<()> {
    if slot.replace(PathBuf::from(argument)).is_some() { bail!("{option} may be specified once") }
    Ok(())
}

fn insert_image(images: &mut BTreeMap<String, PathBuf>, argument: &OsString) -> Result<()> {
    let value = argument.to_str().context("--image NAME=PATH must be UTF-8")?;
    let (name, path) = value.split_once('=').context("--image requires NAME=PATH")?;
    if name.is_empty() || path.is_empty() { bail!("--image requires non-empty NAME=PATH") }
    if images.insert(name.to_owned(), PathBuf::from(path)).is_some() {
        bail!("replacement image {name:?} was specified more than once")
    }
    Ok(())
}

fn parse_full(program: &OsString, values: &[OsString]) -> Result<FullArgs> {
    let mut positional = Vec::new();
    let mut output = None;
    let mut root = None;
    let mut bl = None;
    let mut bl_output = None;
    let mut aosp_zip = None;
    let mut images = BTreeMap::new();
    let mut logical = BTreeMap::new();
    let mut super_image = None;
    let mut force = false;
    let mut options = true;
    let mut at = 0;
    while at < values.len() {
        let item = &values[at];
        if options && item == "--" { options = false; at += 1; continue }
        if options && item == "--force" { force = true; at += 1; continue }
        if options {
            match item.to_str() {
                Some("-o" | "--output") => {
                    let argument = value(values, &mut at, &item.to_string_lossy(), program)?;
                    set_path(&mut output, argument, "--output")?;
                    at += 1;
                    continue
                }
                Some("--root") => {
                    let argument = value(values, &mut at, "--root", program)?;
                    set_path(&mut root, argument, "--root")?;
                    at += 1;
                    continue
                }
                Some("--bl") => {
                    let argument = value(values, &mut at, "--bl", program)?;
                    set_path(&mut bl, argument, "--bl")?;
                    at += 1;
                    continue
                }
                Some("--bl-output") => {
                    let argument = value(values, &mut at, "--bl-output", program)?;
                    set_path(&mut bl_output, argument, "--bl-output")?;
                    at += 1;
                    continue
                }
                Some("--aosp-zip") => {
                    let argument = value(values, &mut at, "--aosp-zip", program)?;
                    set_path(&mut aosp_zip, argument, "--aosp-zip")?;
                    at += 1;
                    continue
                }
                Some("--super") => {
                    let argument = value(values, &mut at, "--super", program)?;
                    set_path(&mut super_image, argument, "--super")?;
                    at += 1;
                    continue
                }
                Some("--image") => {
                    let argument = value(values, &mut at, "--image", program)?;
                    insert_image(&mut images, argument)?;
                    at += 1;
                    continue
                }
                Some("--logical") => {
                    let argument = value(values, &mut at, "--logical", program)?;
                    insert_image(&mut logical, argument)?;
                    at += 1;
                    continue
                }
                _ => {}
            }
        }
        if options && item.to_string_lossy().starts_with('-') {
            bail!("unknown option {}\n{}", item.to_string_lossy(), usage(program))
        }
        positional.push(PathBuf::from(item));
        at += 1;
    }
    if positional.len() != 3 { bail!("AP, CP, and CSC paths are required\n{}", usage(program)) }
    if bl.is_none() { bail!("--bl BL_RESIGNED is required") }
    if bl_output.is_none() { bl_output = bl.clone(); }
    Ok(FullArgs {
        ap: positional.remove(0),
        cp: positional.remove(0),
        csc: positional.remove(0),
        bl,
        bl_output,
        aosp_zip,
        images,
        logical,
        super_image,
        output: output.unwrap_or(env::current_dir()?.join("AP_RESIGNED.tar.md5")),
        root,
        force,
    })
}

fn parse_sign_image(program: &OsString, values: &[OsString]) -> Result<SignImageArgs> {
    let mut source = None;
    let mut name = None;
    let mut root = None;
    let mut force = false;
    let mut positional = Vec::new();
    let mut options = true;
    let mut at = 0;
    while at < values.len() {
        let item = &values[at];
        if options && item == "--" { options = false; at += 1; continue }
        if options && item == "--force" { force = true; at += 1; continue }
        if options {
            match item.to_str() {
                Some("--from") => {
                    let argument = value(values, &mut at, "--from", program)?;
                    set_path(&mut source, argument, "--from")?;
                    at += 1;
                    continue
                }
                Some("--name") => {
                    let argument = value(values, &mut at, "--name", program)?;
                    let argument = argument.to_str().context("--name must be UTF-8")?;
                    if argument.is_empty() { bail!("--name cannot be empty") }
                    if name.replace(argument.to_owned()).is_some() { bail!("--name may be specified once") }
                    at += 1;
                    continue
                }
                Some("--root") => {
                    let argument = value(values, &mut at, "--root", program)?;
                    set_path(&mut root, argument, "--root")?;
                    at += 1;
                    continue
                }
                _ => {}
            }
        }
        if options && item.to_string_lossy().starts_with('-') {
            bail!("unknown sign-image option {}\n{}", item.to_string_lossy(), usage(program))
        }
        positional.push(PathBuf::from(item));
        at += 1;
    }
    if positional.len() != 2 { bail!("sign-image requires INPUT and OUTPUT paths") }
    Ok(SignImageArgs {
        source: source.context("sign-image requires --from")?,
        name: name.context("sign-image requires --name")?,
        input: positional.remove(0),
        output: positional.remove(0),
        root,
        force,
    })
}

fn parse_build_vbmeta(program: &OsString, values: &[OsString]) -> Result<BuildVbmetaArgs> {
    let mut source = None;
    let mut output = None;
    let mut root = None;
    let mut images = BTreeMap::new();
    let mut force = false;
    let mut at = 0;
    while at < values.len() {
        let item = values[at].to_string_lossy();
        match item.as_ref() {
            "--from" => {
                let argument = value(values, &mut at, "--from", program)?;
                set_path(&mut source, argument, "--from")?;
            }
            "-o" | "--output" => {
                let argument = value(values, &mut at, &item, program)?;
                set_path(&mut output, argument, "--output")?;
            }
            "--root" => {
                let argument = value(values, &mut at, "--root", program)?;
                set_path(&mut root, argument, "--root")?;
            }
            "--image" => {
                let argument = value(values, &mut at, "--image", program)?;
                insert_image(&mut images, argument)?;
            }
            "--force" => { force = true; at += 1; continue }
            _ => bail!("unknown build-vbmeta option {item}\n{}", usage(program)),
        }
        at += 1;
    }
    if images.is_empty() { bail!("build-vbmeta requires at least one --image NAME=PATH") }
    Ok(BuildVbmetaArgs {
        source: source.context("build-vbmeta requires --from")?,
        images,
        output: output.context("build-vbmeta requires -o/--output")?,
        root,
        force,
    })
}

fn parse_update_ap(program: &OsString, values: &[OsString]) -> Result<UpdateApArgs> {
    let mut base = None;
    let mut bl = None;
    let mut bl_output = None;
    let mut aosp_zip = None;
    let mut output = None;
    let mut root = None;
    let mut images = BTreeMap::new();
    let mut logical = BTreeMap::new();
    let mut incremental = false;
    let mut force = false;
    let mut at = 0;
    while at < values.len() {
        let item = values[at].to_string_lossy();
        match item.as_ref() {
            "--base" => {
                let argument = value(values, &mut at, "--base", program)?;
                set_path(&mut base, argument, "--base")?;
            }
            "--bl" => {
                let argument = value(values, &mut at, "--bl", program)?;
                set_path(&mut bl, argument, "--bl")?;
            }
            "--bl-output" => {
                let argument = value(values, &mut at, "--bl-output", program)?;
                set_path(&mut bl_output, argument, "--bl-output")?;
            }
            "--aosp-zip" => {
                let argument = value(values, &mut at, "--aosp-zip", program)?;
                set_path(&mut aosp_zip, argument, "--aosp-zip")?;
            }
            "-o" | "--output" => {
                let argument = value(values, &mut at, &item, program)?;
                set_path(&mut output, argument, "--output")?;
            }
            "--root" => {
                let argument = value(values, &mut at, "--root", program)?;
                set_path(&mut root, argument, "--root")?;
            }
            "--image" => {
                let argument = value(values, &mut at, "--image", program)?;
                insert_image(&mut images, argument)?;
            }
            "--logical" => {
                let argument = value(values, &mut at, "--logical", program)?;
                insert_image(&mut logical, argument)?;
            }
            "--incremental" => { incremental = true; at += 1; continue }
            "--force" => { force = true; at += 1; continue }
            _ => bail!("unknown update-ap option {item}\n{}", usage(program)),
        }
        at += 1;
    }
    if bl_output.is_some() && bl.is_none() { bail!("--bl-output requires --bl") }
    if bl_output.is_none() { bl_output = bl.clone(); }
    let base = base.context("update-ap requires --base")?;
    let output = output.unwrap_or(if incremental { env::current_dir()?.join("INCREMENTAL.tar.md5") } else { base.clone() });
    let force = force || output == base || bl.as_ref().zip(bl_output.as_ref()).is_some_and(|(base, output)| base == output);
    Ok(UpdateApArgs {
        base,
        bl,
        bl_output,
        aosp_zip,
        images,
        logical,
        incremental,
        output,
        root,
        force,
    })
}

fn parse_from(raw: impl IntoIterator<Item = OsString>) -> Result<(Soc, Command)> {
    let mut raw = raw.into_iter();
    let program = raw.next().unwrap_or_else(|| "android-resigner".into());
    let mut values = raw.collect::<Vec<_>>();
    if values.first().and_then(|item| item.to_str()) != Some("--soc") {
        bail!("--soc is required\n{}", usage(&program))
    }
    if values.len() < 2 { bail!("--soc needs a value\n{}", usage(&program)) }
    let soc = Soc::parse(values[1].to_str().context("--soc must be UTF-8")?)?;
    values.drain(..2);
    let cmd = match values.first().and_then(|item| item.to_str()) {
        Some("sign-image") => Command::SignImage(parse_sign_image(&program, &values[1..])?),
        Some("build-vbmeta") => Command::BuildVbmeta(parse_build_vbmeta(&program, &values[1..])?),
        Some("update-ap") => Command::UpdateAp(parse_update_ap(&program, &values[1..])?),
        Some("build-ap") => Command::BuildAp(parse_full(&program, &values[1..])?),
        Some("full") => Command::Full(parse_full(&program, &values[1..])?),
        _ => Command::Full(parse_full(&program, &values)?),
    };
    Ok((soc, cmd))
}

fn parse() -> Result<(Soc, Command)> { parse_from(env::args_os()) }

fn full_options(soc: Soc, args: FullArgs) -> RunOptions {
    RunOptions {
        soc,
        ap: args.ap,
        cp: args.cp,
        csc: args.csc,
        bl: args.bl,
        bl_output: args.bl_output,
        aosp_zip: args.aosp_zip,
        images: args.images,
        logical: args.logical,
        super_image: args.super_image,
        output: args.output,
        root: args.root,
        force: args.force,
    }
}

fn run() -> Result<()> {
    let (soc, command) = parse()?;
    let output = match command {
        Command::SignImage(args) => sign_image(SignImageOptions {
            soc,
            source: args.source,
            name: args.name,
            input: args.input,
            output: args.output,
            root: args.root,
            force: args.force,
        })?,
        Command::BuildVbmeta(args) => build_vbmeta(BuildVbmetaOptions {
            soc,
            source: args.source,
            images: args.images,
            output: args.output,
            root: args.root,
            force: args.force,
        })?,
        Command::UpdateAp(args) => update_ap(UpdateApOptions {
            soc,
            base: args.base,
            bl: args.bl,
            bl_output: args.bl_output,
            aosp_zip: args.aosp_zip,
            images: args.images,
            logical: args.logical,
            incremental: args.incremental,
            output: args.output,
            root: args.root,
            force: args.force,
        })?,
        Command::BuildAp(args) | Command::Full(args) => android_resigner::resign::run(full_options(soc, args))?,
    };
    println!("{}", output.display());
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = android_resigner::cancel::install() {
        eprintln!("Error: installing signal handlers: {error}");
        return ExitCode::FAILURE
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) if android_resigner::cancel::cancelled() => { eprintln!("Cancelled"); ExitCode::from(130) }
        Err(error) => { eprintln!("Error: {error:#}"); ExitCode::FAILURE }
    }
}
