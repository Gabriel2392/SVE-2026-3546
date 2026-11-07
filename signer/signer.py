#!/usr/bin/env python3
import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

import lz4.frame

sys.dont_write_bytecode = True

import avb
import cs
from layout import SOCS, Image, Layout, Part, get


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fw_version(images: dict[str, bytes], layout: Layout) -> str:
    pattern = re.compile(rb"(?<![A-Z0-9])[A-Z][0-9]{3}[A-Z][A-Z0-9]{8}(?![A-Z0-9])")
    versions = set()
    for img in layout.images:
        if not img.version:
            continue
        found = {item.decode("ascii") for item in pattern.findall(images[img.name])}
        if len(found) != 1:
            raise ValueError(f"cannot derive one firmware version from {img.name}")
        versions.update(found)
    if len(versions) != 1:
        raise ValueError(f"bootloader images contain different versions: {sorted(versions)}")
    return versions.pop()


def _empty(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise ValueError(f"directory is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def _archive(path: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(path, "r:*") as tar:
        for item in tar.getmembers():
            if not item.isfile() or not item.name.endswith(".lz4"):
                continue
            name = item.name.removesuffix(".lz4")
            if Path(name).name != name or name in out:
                raise ValueError(f"invalid archive member: {item.name}")
            src = tar.extractfile(item)
            if src is None:
                raise ValueError(f"cannot read {item.name}")
            out[name] = lz4.frame.decompress(src.read())
    if not out:
        raise ValueError("archive has no LZ4 images")
    return out


def _directory(path: Path, layout: Layout) -> dict[str, bytes]:
    found = []
    known = set().union(*(get(soc).names for soc in SOCS))
    roots = [path, *(item for item in path.rglob("*") if item.is_dir())]
    for root in roots:
        raw = {item.name: item.read_bytes() for item in root.iterdir()
               if item.is_file() and item.name in known}
        packed = {item.name.removesuffix(".lz4"): lz4.frame.decompress(item.read_bytes())
                  for item in root.iterdir()
                  if item.is_file() and item.name.endswith(".lz4")}
        for images in (raw, packed):
            if set(images) == layout.names:
                found.append(images)
    if len(found) != 1:
        raise ValueError("cannot resolve one complete BL image directory")
    return found[0]


def _members(path: Path, layout: Layout) -> dict[str, bytes]:
    if path.is_file():
        return _archive(path)
    if not path.is_dir():
        raise ValueError(f"source does not exist: {path}")
    return _directory(path, layout)


def _check(images: dict[str, bytes], layout: Layout) -> None:
    if set(images) != layout.names:
        raise ValueError("image set does not match the selected profile")
    for img in layout.images:
        data = images.get(img.name)
        if not data:
            raise ValueError(f"image is missing or empty: {img.name}")
        cursor = 0
        for part in img.parts:
            end = len(data) if part.end is None else part.end
            if part.start != cursor or not part.start < end <= len(data):
                raise ValueError(f"invalid layout for {img.name}/{part.name}")
            cursor = end
        if img.parts and cursor != len(data):
            raise ValueError(f"layout does not cover {img.name}")
    fw_version(images, layout)


def _part_dir(root: Path, img: Image) -> Path:
    return root / Path(img.name).stem


def _write(images: dict[str, bytes], layout: Layout,
           work: Path, src: Path) -> None:
    _check(images, layout)
    _empty(work)
    for img in layout.images:
        data = images[img.name]
        (work / img.name).write_bytes(data)
        if img.parts:
            dst = _part_dir(work, img)
            dst.mkdir()
            for part in img.parts:
                (dst / part.name).write_bytes(data[part.start:part.end])
    meta = {
        "profile": layout.soc,
        "version": fw_version(images, layout),
        "source": str(src.resolve()),
        "images": {
            img.name: {"size": len(images[img.name]), "sha256": sha256(images[img.name])}
            for img in layout.images
        },
    }
    (work / "layout.json").write_text(json.dumps(meta, indent=2) + "\n")


def load_stock(src: Path, soc: str) -> tuple[Layout, dict[str, bytes]]:
    layout = get(soc)
    images = _members(src, layout)
    _check(images, layout)
    check(images, layout)
    return layout, images


def prepare(src: Path, work: Path, soc: str) -> None:
    layout, images = load_stock(src, soc)
    _write(images, layout, work, src)
    print(work)


def _read(root: Path, img: Image, size: int) -> bytearray:
    if not img.parts:
        data = bytearray((root / img.name).read_bytes())
        if len(data) != size:
            raise ValueError(f"size mismatch for {img.name}")
        return data
    out = bytearray()
    src = _part_dir(root, img)
    for part in img.parts:
        data = (src / part.name).read_bytes()
        if part.size is not None and len(data) != part.size:
            raise ValueError(f"size mismatch for {img.name}/{part.name}")
        out.extend(data)
    if len(out) != size:
        raise ValueError(f"rebuilt size mismatch for {img.name}")
    return out


def _sign_part(data: bytearray, part: Part, layout: Layout,
               keys: cs.Keys, rb: int | None) -> None:
    if part.avb_keys:
        cs.replace_avb_keys(data, keys.avb_pub)
        cs.provision_fw_key(data, cs.pub_blob(keys.ree))
    if part.stage == "st1":
        cs.sign_st1(data, keys, rb, layout.signing_type)
    elif part.stage == "st2":
        if part.key is None:
            raise ValueError(f"missing key mode for {part.name}")
        cs.sign_st2(data, keys, part.key, part.header, rb, layout.signing_type)


def _check_index(rec: dict, keys: cs.Keys | None, mode: str) -> None:
    if keys is None:
        return
    want = zlib.crc32(cs.pub_blob(keys.key(mode)))
    if rec["key_index"] != f"{want:08x}":
        raise ValueError(f"ST2 key index mismatch for {mode}")


def _build(root: Path, layout: Layout, keys: cs.Keys,
           rb: int | None) -> dict[str, bytes]:
    meta = json.loads((root / "layout.json").read_text())
    sizes = {name: int(item["size"]) for name, item in meta["images"].items()}
    images = {}
    for img in layout.images:
        if img.name == layout.vbmeta_image:
            continue
        data = _read(root, img, sizes[img.name])
        if img.preserve and sha256(data) != meta["images"][img.name]["sha256"]:
            raise ValueError(f"preserved image changed: {img.name}")
        if img.parts:
            data.clear()
            src = _part_dir(root, img)
            for part in img.parts:
                chunk = bytearray((src / part.name).read_bytes())
                _sign_part(chunk, part, layout, keys, rb)
                data.extend(chunk)
        if img.stage == "st2":
            if img.key is None:
                raise ValueError(f"missing key mode for {img.name}")
            cs.sign_st2(data, keys, img.key, False, rb, layout.signing_type)
        images[img.name] = bytes(data)

    updates = {}
    for img in layout.images:
        if img.avb is None:
            continue
        data = bytearray(images[img.name])
        updates[img.avb] = avb.wrap(data, keys.avb, keys.avb_pub, img.avb)
        images[img.name] = bytes(data)

    vbmeta = _read(root, layout.by_name[layout.vbmeta_image],
                   sizes[layout.vbmeta_image])
    avb.update_top(vbmeta, keys.avb, keys.avb_pub, updates)
    cs.sign_st2(vbmeta, keys, "ree", False, rb, layout.signing_type)
    images[layout.vbmeta_image] = bytes(vbmeta)
    return images


def sign_images(stock: dict[str, bytes], layout: Layout, keys: cs.Keys,
                rb: int | None = None) -> tuple[dict[str, bytes], dict]:
    with tempfile.TemporaryDirectory(prefix=f"{layout.soc}-sign-") as tmp:
        work = Path(tmp) / "work"
        _write(stock, layout, work, Path("stock"))
        images = _build(work, layout, keys, rb)
    return images, check(images, layout, keys)


def _mode(img: Image, part: Part | None = None) -> str:
    item = part or img
    if isinstance(item, Image) and item.preserve:
        return "preserved"
    if item.stage is None:
        return "unsigned"
    if item.stage == "st1":
        return "CodeSigner v5 ST1"
    return f"CodeSigner v5 ST2 {item.key.upper()}"


def check(images: dict[str, bytes], layout: Layout,
          keys: cs.Keys | None = None) -> dict:
    _check(images, layout)
    fld = images[layout.key_image]
    stock_tee, stock_ree = cs.stock_keys(fld, layout.signing_type)
    tee = keys.tee.public_key() if keys else stock_tee
    ree = keys.ree.public_key() if keys else stock_ree
    info = {"soc": layout.soc, "version": fw_version(images, layout), "images": {}}
    updates = {}

    for img in layout.images:
        data = images.get(img.name)
        item = {
            "size": len(data),
            "sha256": sha256(data),
            "mode": _mode(img),
            "parts": [],
        }
        for part in img.parts:
            raw = data[part.start:part.end]
            rec = {"name": part.name, "size": len(raw), "mode": _mode(img, part)}
            if part.stage == "st1":
                rec.update(cs.verify_st1(raw, keys, layout.signing_type))
            elif part.stage == "st2":
                pub = tee if part.key == "tee" else ree
                rec.update(cs.verify_st2(
                    raw, pub, part.key or "", part.header, layout.signing_type
                ))
                _check_index(rec, keys, part.key or "")
            if part.avb_keys and keys is not None:
                check = bytearray(raw)
                rec["avb_key_offsets"] = [f"{off:#x}" for off in cs.replace_avb_keys(check, keys.avb_pub)]
                rec["firmware_key_offset"] = f"{cs.provision_fw_key(check, cs.pub_blob(keys.ree)):#x}"
                if check != raw:
                    raise ValueError("keystorage keys were not replaced")
            item["parts"].append(rec)
        if img.stage == "st2":
            item.update(cs.verify_st2(
                data, ree if img.key == "ree" else tee,
                img.key or "", False, layout.signing_type
            ))
            _check_index(item, keys, img.key or "")
        if img.avb:
            pub = keys.avb_pub if keys else None
            updates[img.avb] = avb.verify_wrap(data, pub, img.avb)
            item["avb"] = "SHA256_RSA4096"
        info["images"][img.name] = item

    vbmeta = images[layout.vbmeta_image]
    top_pub = keys.avb_pub if keys else avb.public(vbmeta)
    avb.verify_top(vbmeta, top_pub, updates)
    info["images"][layout.vbmeta_image]["avb"] = "SHA256_RSA4096"
    info["ok"] = True
    return info


def _tar(images: dict[str, bytes], layout: Layout,
         path: Path, tar_name: str | None = None) -> None:
    tar_name = tar_name or path.name.removesuffix(".md5")
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
        for img in layout.images:
            packed = lz4.frame.compress(
                images[img.name],
                block_size=lz4.frame.BLOCKSIZE_MAX1MB,
                block_linked=False,
                content_checksum=True,
                store_size=True,
            )
            info = tarfile.TarInfo(f"{img.name}.lz4")
            info.size = len(packed)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            tar.addfile(info, io.BytesIO(packed))
    raw = path.read_bytes()
    digest = hashlib.md5(raw).hexdigest()
    with path.open("ab") as out:
        out.write(f"{digest}  {tar_name}\n".encode("ascii"))


def write_tar(images: dict[str, bytes], layout: Layout, path: Path,
              tar_name: str | None = None) -> None:
    _tar(images, layout, path, tar_name)


def build(work: Path, key_dir: Path, out: Path,
          soc: str, rb: int | None) -> None:
    meta_path = work / "layout.json"
    if not meta_path.is_file():
        raise ValueError("work directory was not prepared by this signer")
    meta = json.loads(meta_path.read_text())
    if meta.get("profile") != soc:
        raise ValueError(f"work directory does not match --soc {soc}")
    layout = get(soc)
    keys = cs.Keys.load(key_dir)
    images = _build(work, layout, keys, rb)
    info = check(images, layout, keys)
    _empty(out)
    raw = out / "images"
    raw.mkdir()
    for img in layout.images:
        (raw / img.name).write_bytes(images[img.name])
    (out / "check.json").write_text(json.dumps(info, indent=2) + "\n")
    archive = out / f"BL_{fw_version(images, layout)}_CUSTOM.tar.md5"
    _tar(images, layout, archive)
    print(archive)


def run_check(path: Path, key_path: Path | None, soc: str) -> None:
    keys = cs.Keys.load(key_path) if key_path else None
    layout, images = load_stock(path, soc)
    print(json.dumps(check(images, layout, keys), indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(prog="exynos-bl-signer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("source", type=Path)
    prep.add_argument("work", type=Path)
    prep.add_argument("--soc", required=True, choices=SOCS)
    make = sub.add_parser("build")
    make.add_argument("work", type=Path)
    make.add_argument("keys", type=Path)
    make.add_argument("output", type=Path)
    make.add_argument("--soc", required=True, choices=SOCS)
    make.add_argument("--rollback", type=lambda val: int(val, 0))
    chk = sub.add_parser("check")
    chk.add_argument("images", type=Path)
    chk.add_argument("--keys", type=Path)
    chk.add_argument("--soc", required=True, choices=SOCS)
    a = ap.parse_args()
    if a.cmd == "prepare":
        prepare(a.source, a.work, a.soc)
    elif a.cmd == "build":
        build(a.work, a.keys, a.output, a.soc, a.rollback)
    else:
        run_check(a.images, a.keys, a.soc)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"error: {exc}")
