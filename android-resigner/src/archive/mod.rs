mod tar;
mod zip;

pub use tar::{IndexedTarEntry, TarIndex, TarMetadata};
pub use zip::{Zip, ZipEntry};

use std::{io, path::{Component, Path, PathBuf}};

pub fn safe_path(name: &str) -> io::Result<PathBuf> {
    if name.is_empty() || name.contains('\0') || name.contains('\\') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsafe archive path"));
    }
    let path = Path::new(name);
    if path.is_absolute() || path.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsafe archive path: {name}")));
    }
    Ok(path.into())
}
