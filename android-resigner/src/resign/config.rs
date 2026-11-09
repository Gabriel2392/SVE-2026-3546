use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::graph::DependencyGraph;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub soc: String,
    pub signing: Signing,
    pub android: Android,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub codesigner_type: u32,
    pub st2_tee_key: String,
    pub st2_ree_key: String,
    pub avb_private_key: String,
    pub avb_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Android {
    pub archive: Vec<String>,
    pub super_image: String,
    pub vbmeta: Vec<String>,
    pub st2_key_type: u32,
    pub avb_algorithm: String,
    #[serde(default)]
    pub image_rules: BTreeMap<String, ImageRule>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub logical_rules: BTreeMap<String, ImageRule>,
    pub avb_generation: AvbGenerationPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CodeSignerKind {
    None,
    Normal,
    Sparse,
    StandaloneVbmeta,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyPolicy {
    Auto,
    Tee,
    Ree,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AvbKind {
    None,
    Hash,
    Hashtree,
    Standalone,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvbGenerationPolicy {
    pub data_block: u32,
    pub hash_block: u32,
    pub fec_roots: u32,
    pub flags: u32,
    pub rollback_index: u64,
    pub rollback_location: u32,
    pub footer_version_major: u32,
    pub footer_version_minor: u32,
    pub release: String,
    pub salt: SaltPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SaltPolicy {
    Stock,
    Zero,
    Fixed { hex: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRule {
    pub codesigner: CodeSignerKind,
    pub key: KeyPolicy,
    pub avb: AvbKind,
    pub partition: String,
    #[serde(default)]
    pub synthesize_missing_wrappers: bool,
    #[serde(default)]
    pub ramdisk: Option<Ramdisk>,
    #[serde(default)]
    pub filesystem: Option<Filesystem>,
    #[serde(default)]
    pub super_image: bool,
    #[serde(default)]
    pub optional: bool,
}

impl ImageRule {
    pub(super) fn signs_firmware(&self) -> bool {
        self.ramdisk.as_ref().is_some_and(|rule| rule.discover_firmware || !rule.firmware.is_empty())
            || self.filesystem.as_ref().is_some_and(|rule| rule.discover_firmware || !rule.sign_firmware.is_empty())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ramdisk {
    pub names: Vec<String>,
    #[serde(default)]
    pub discover_firmware: bool,
    #[serde(default)]
    pub firmware: Vec<String>,
    #[serde(default = "yes")]
    pub require_all: bool,
}

fn yes() -> bool { true }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    #[serde(default)]
    pub discover_firmware: bool,
    #[serde(default)]
    pub preserve_stock: Vec<String>,
    #[serde(default)]
    pub sign_firmware: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub remove_if_present: Vec<String>,
}

fn safe_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != ".."
}

fn safe_posix(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.contains('\\') && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn validate_ramdisk(name: &str, rules: &Ramdisk) -> Result<()> {
    if rules.names.is_empty() || rules.names.iter().any(|name| !safe_name(name)) {
        bail!("invalid ramdisk names for {name}")
    }
    let mut paths = BTreeSet::new();
    for path in &rules.firmware {
        if !safe_posix(path) || !paths.insert(path) {
            bail!("invalid or duplicate ramdisk firmware path {path:?} for {name}")
        }
    }
    Ok(())
}

fn validate_filesystem(name: &str, rules: &Filesystem) -> Result<()> {
    let mut paths = BTreeSet::new();
    for path in rules.preserve_stock.iter().chain(&rules.sign_firmware) {
        if !safe_posix(path) { bail!("unsafe filesystem path {path:?} in {name}") }
        if !paths.insert(path) { bail!("duplicate filesystem path {path:?} in {name}") }
    }
    for path in rules.remove.iter().chain(&rules.remove_if_present) {
        if !safe_posix(path) { bail!("unsafe filesystem removal path {path:?} in {name}") }
        if !paths.insert(path) { bail!("duplicate filesystem path {path:?} in {name}") }
    }
    Ok(())
}

fn validate_avb_generation(policy: &AvbGenerationPolicy) -> Result<()> {
    if policy.data_block < 512 || !policy.data_block.is_power_of_two()
        || policy.hash_block < 512 || !policy.hash_block.is_power_of_two()
        || policy.data_block != policy.hash_block || policy.fec_roots >= 255
        || policy.flags & !3 != 0 || policy.release.len() > 47 || !policy.release.is_ascii()
        || policy.footer_version_major != 1 {
        bail!("invalid android.avb_generation policy")
    }
    if let SaltPolicy::Fixed { hex } = &policy.salt {
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("android.avb_generation fixed salt must be 32-byte hexadecimal")
        }
    }
    Ok(())
}

impl Config {
    pub fn load_path(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_slice(&data).with_context(|| format!("invalid {}", path.display()))
    }

    pub fn validate_image_rules(&self) -> Result<()> {
        validate_avb_generation(&self.android.avb_generation)?;
        if self.android.image_rules.is_empty() {
            return Ok(())
        }

        let mut expected = BTreeSet::new();
        for name in self.android.archive.iter().chain(&self.android.vbmeta) {
            if !expected.insert(name) { bail!("duplicate Android target {name}") }
        }
        let actual = self.android.image_rules.keys().collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().cloned().collect::<Vec<_>>();
            let extra = actual.difference(&expected).copied().cloned().collect::<Vec<_>>();
            bail!("image_rules do not exactly cover Android archive/vbmeta targets: missing={missing:?}, extra={extra:?}")
        }

        let mut partitions = BTreeSet::new();
        for (name, rule) in &self.android.image_rules {
            if !safe_name(name) || !safe_name(&rule.partition) {
                bail!("unsafe image rule {name:?} -> partition {:?}", rule.partition)
            }
            if !partitions.insert(&rule.partition) {
                bail!("duplicate image-rule partition {}", rule.partition)
            }
            if rule.codesigner == CodeSignerKind::None && rule.key != KeyPolicy::Auto {
                bail!("{name}: a CodeSigner-free image must use key policy auto")
            }
            if rule.synthesize_missing_wrappers
                && rule.codesigner == CodeSignerKind::None && rule.avb == AvbKind::None
            {
                bail!("{name}: wrapper synthesis requires CodeSigner or AVB metadata")
            }
            let standalone_code = rule.codesigner == CodeSignerKind::StandaloneVbmeta;
            let standalone_avb = rule.avb == AvbKind::Standalone;
            if standalone_code != standalone_avb {
                bail!("{name}: standalone-vbmeta CodeSigner and standalone AVB must be selected together")
            }

            let is_super = name == &self.android.super_image;
            if rule.super_image != is_super {
                bail!("{name}: super_image must be true exactly for {}", self.android.super_image)
            }
            if is_super
                && (rule.codesigner != CodeSignerKind::Sparse
                    || rule.avb != AvbKind::None
                    || rule.ramdisk.is_some())
            {
                bail!("{name}: super requires sparse CodeSigner, no outer AVB, and no ramdisk rule")
            }

            let is_vbmeta = self.android.vbmeta.iter().any(|item| item == name);
            if is_vbmeta {
                if !standalone_code || rule.super_image || rule.ramdisk.is_some() || rule.filesystem.is_some() {
                    bail!("{name}: vbmeta targets require standalone wrappers and cannot have nested-content rules")
                }
            } else if standalone_code {
                bail!("{name}: standalone vbmeta wrappers are only valid for configured vbmeta targets")
            }

            if let Some(ramdisk) = &rule.ramdisk {
                if rule.codesigner != CodeSignerKind::Normal || rule.avb != AvbKind::Hash {
                    bail!("{name}: ramdisk discovery requires a normal CodeSigner image with AVB hash integrity")
                }
                validate_ramdisk(name, ramdisk)?;
            }
            if let Some(filesystem) = &rule.filesystem {
                if !rule.super_image && rule.avb != AvbKind::Hashtree {
                    bail!("{name}: filesystem discovery requires AVB hashtree integrity or a super container")
                }
                validate_filesystem(name, filesystem)?;
            }

        }

        for (name, rule) in &self.android.logical_rules {
            if self.android.image_rules.contains_key(name) { bail!("logical rule duplicates physical target {name}") }
            if !safe_name(name) || !name.ends_with(".img") || !safe_name(&rule.partition) {
                bail!("unsafe logical image rule {name:?} -> partition {:?}", rule.partition)
            }
            if !partitions.insert(&rule.partition) { bail!("duplicate image-rule partition {}", rule.partition) }
            if rule.codesigner != CodeSignerKind::None || rule.key != KeyPolicy::Auto || rule.super_image
                || rule.ramdisk.is_some() || !matches!(rule.avb, AvbKind::Hash | AvbKind::Hashtree) {
                bail!("{name}: logical partitions require no CodeSigner, auto key policy, hash/hashtree AVB, and no ramdisk/super flag")
            }
            if let Some(filesystem) = &rule.filesystem {
                if rule.avb != AvbKind::Hashtree { bail!("{name}: filesystem discovery requires AVB hashtree integrity") }
                validate_filesystem(name, filesystem)?;
            }
        }
        if !self.android.dependencies.is_empty() {
            let nodes = self.android.image_rules.keys().chain(self.android.logical_rules.keys()).cloned().collect::<Vec<_>>();
            DependencyGraph::new(nodes, &self.android.dependencies)?;
        }
        Ok(())
    }

}
