use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use ecdsa::RecoveryId;
use p384::{EncodedPoint, ecdsa::{Signature, SigningKey, VerifyingKey, signature::hazmat::{PrehashSigner, PrehashVerifier}}, pkcs8::DecodePrivateKey};
use rsa::{BigUint, RsaPrivateKey, traits::PublicKeyParts};

pub struct Keys {
    pub tee: SigningKey,
    pub ree: SigningKey,
    pub avb: RsaPrivateKey,
    pub avb_public: Vec<u8>,
}

fn ec_key(path: &Path) -> Result<SigningKey> {
    let pem = fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem).with_context(|| format!("invalid P-384 key {}", path.display()))
}

impl Keys {
    pub fn load(resources: &Path, config: &super::config::Signing) -> Result<Self> {
        let avb = RsaPrivateKey::read_pkcs8_pem_file(resources.join(&config.avb_private_key))
            .with_context(|| format!("invalid RSA key {}", resources.join(&config.avb_private_key).display()))?;
        let avb_public = fs::read(resources.join(&config.avb_public_key))?;
        if avb_public.len() != 1032 || u32::from_be_bytes(avb_public[..4].try_into().unwrap()) != 4096
            || BigUint::from_bytes_be(&avb_public[8..520]) != avb.n().to_owned() {
            bail!("AVB public key is not RSA-4096 or does not match the private key")
        }
        Ok(Self {
            tee: ec_key(&resources.join(&config.st2_tee_key))?,
            ree: ec_key(&resources.join(&config.st2_ree_key))?,
            avb,
            avb_public,
        })
    }

    pub fn st2(&self, key_type: u32) -> Result<&SigningKey> {
        match key_type {
            0 => Ok(&self.tee),
            1 => Ok(&self.ree),
            value => bail!("unsupported ST2 key type {value}"),
        }
    }
}

pub fn verifying_blob(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    let mut blob = vec![0; 524];
    blob[20..68].copy_from_slice(point.x().unwrap());
    blob[88..136].copy_from_slice(point.y().unwrap());
    blob
}

pub fn public_blob(key: &SigningKey) -> Vec<u8> { verifying_blob(key.verifying_key()) }

pub fn padded_signature(key: &SigningKey, digest: &[u8]) -> Result<[u8; 136]> {
    if digest.len() != 64 { bail!("P-384 CodeSigner digest is not SHA-512") }
    let signature: Signature = key.sign_prehash(digest).context("P-384 signing failed")?;
    let mut encoded = [0u8; 136];
    encoded[20..68].copy_from_slice(&signature.r().to_bytes());
    encoded[88..136].copy_from_slice(&signature.s().to_bytes());
    Ok(encoded)
}

pub fn verify_padded(key: &VerifyingKey, digest: &[u8], encoded: &[u8]) -> bool {
    if digest.len() != 64 || encoded.len() != 136 || encoded[..20].iter().any(|&b| b != 0) || encoded[68..88].iter().any(|&b| b != 0) { return false }
    let r: [u8; 48] = encoded[20..68].try_into().unwrap();
    let s: [u8; 48] = encoded[88..136].try_into().unwrap();
    let Ok(signature) = Signature::from_scalars(r, s) else { return false };
    key.verify_prehash(digest, &signature).is_ok()
}

pub fn recover_padded(digest: &[u8], encoded: &[u8], index: u32) -> Result<Option<VerifyingKey>> {
    if digest.len() != 64 || encoded.len() != 136 || encoded[..20].iter().any(|&b| b != 0)
        || encoded[68..88].iter().any(|&b| b != 0) { return Ok(None) }
    let r: [u8; 48] = encoded[20..68].try_into().unwrap();
    let s: [u8; 48] = encoded[88..136].try_into().unwrap();
    let Ok(signature) = Signature::from_scalars(r, s) else { return Ok(None) };
    let mut found = Vec::new();
    for value in 0..=RecoveryId::MAX {
        let id = RecoveryId::from_byte(value).unwrap();
        let Ok(key) = VerifyingKey::recover_from_prehash(digest, &signature, id) else { continue };
        if crc32fast::hash(&verifying_blob(&key)) == index && verify_padded(&key, digest, encoded)
            && !found.iter().any(|old| old == &key) { found.push(key) }
    }
    if found.len() > 1 { bail!("ambiguous P-384 recovered key") }
    Ok(found.pop())
}

fn public_key(data: &[u8]) -> Result<VerifyingKey> {
    if data.len() < 136 || data[..20].iter().any(|&b| b != 0) || data[68..88].iter().any(|&b| b != 0) { bail!("invalid P-384 public key") }
    let mut point = [0; 97]; point[0] = 4; point[1..49].copy_from_slice(&data[20..68]); point[49..].copy_from_slice(&data[88..136]);
    Ok(VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(point)?)?)
}

pub fn sbl1_public_keys(data: &[u8]) -> Result<[VerifyingKey; 2]> {
    if data.len() < 4 { bail!("truncated SBL1") }
    let size = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize * 512;
    if size > data.len() || size < 2360 { bail!("invalid SBL1 size") }
    let at = size - 2360;
    if u32::from_le_bytes(data[at + 8..at + 12].try_into().unwrap()) != 5 { bail!("invalid SBL1 footer") }
    Ok([public_key(&data[at + 100..at + 624])?, public_key(&data[at + 624..at + 1148])?])
}
