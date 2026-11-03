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
from layout import BY_NAME, IMAGES, Image, Part


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fw_version(images: dict[str, bytes]) -> str:
    pattern = re.compile(rb"(?<![A-Z0-9])[A-Z][0-9]{3}[A-Z][A-Z0-9]{8}(?![A-Z0-9])")
    versions = set()
    for img in IMAGES:
        if img.name == "up_param.bin":
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


def _members(path: Path) -> dict[str, bytes]:
    out = {}
    if path.is_file():
        with tarfile.open(path, "r:*") as tar:
            names = {item.name: item for item in tar.getmembers() if item.isfile()}
            for img in IMAGES:
                name = f"{img.name}.lz4"
                item = names.get(name)
                if item is None:
                    raise ValueError(f"archive is missing {name}")
                src = tar.extractfile(item)
                if src is None:
                    raise ValueError(f"cannot read {name}")
                out[img.name] = lz4.frame.decompress(src.read())
        return out
    if not path.is_dir():
        raise ValueError(f"source does not exist: {path}")
    roots = [path]
    roots.extend(item.parent for item in path.rglob("fld.bin.lz4"))
    roots.extend(item.parent for item in path.rglob("fld.bin"))
    valid = []
    for root in dict.fromkeys(roots):
        raw = all((root / img.name).is_file() for img in IMAGES)
        packed = all((root / f"{img.name}.lz4").is_file() for img in IMAGES)
        if raw or packed:
            valid.append((root, packed))
    if len(valid) != 1:
        raise ValueError("cannot resolve one complete BL image directory")
    root, packed = valid[0]
    for img in IMAGES:
        data = (root / (f"{img.name}.lz4" if packed else img.name)).read_bytes()
        out[img.name] = lz4.frame.decompress(data) if packed else data
    return out


def _check(images: dict[str, bytes]) -> None:
    for img in IMAGES:
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
    fw_version(images)


def _part_dir(root: Path, img: Image) -> Path:
    return root / Path(img.name).stem


def _write(images: dict[str, bytes], work: Path, src: Path) -> None:
    _check(images)
    _empty(work)
    for img in IMAGES:
        data = images[img.name]
        (work / img.name).write_bytes(data)
        if img.parts:
            dst = _part_dir(work, img)
            dst.mkdir()
            for part in img.parts:
                (dst / part.name).write_bytes(data[part.start:part.end])
    meta = {
        "version": fw_version(images),
        "source": str(src.resolve()),
        "images": {
            img.name: {"size": len(images[img.name]), "sha256": sha256(images[img.name])}
            for img in IMAGES
        },
    }
    (work / "layout.json").write_text(json.dumps(meta, indent=2) + "\n")


def load_stock(src: Path) -> dict[str, bytes]:
    images = _members(src)
    _check(images)
    check(images)
    return images


def prepare(src: Path, work: Path) -> None:
    images = load_stock(src)
    _write(images, work, src)
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


def _sign_part(data: bytearray, part: Part, keys: cs.Keys,
               rb: int | None) -> None:
    if part.avb_keys:
        cs.replace_avb_keys(data, keys.avb_pub)
    if part.stage == "st1":
        cs.sign_st1(data, keys, rb)
    elif part.stage == "st2":
        if part.key is None:
            raise ValueError(f"missing key mode for {part.name}")
        cs.sign_st2(data, keys, part.key, part.header, rb)


def _check_index(rec: dict, keys: cs.Keys | None, mode: str) -> None:
    if keys is None:
        return
    want = zlib.crc32(cs.pub_blob(keys.key(mode)))
    if rec["key_index"] != f"{want:08x}":
        raise ValueError(f"ST2 key index mismatch for {mode}")


def _build(root: Path, keys: cs.Keys, rb: int | None) -> dict[str, bytes]:
    meta = json.loads((root / "layout.json").read_text())
    sizes = {name: int(item["size"]) for name, item in meta["images"].items()}
    images = {}
    for img in IMAGES:
        if img.name == "vbmeta.img":
            continue
        data = _read(root, img, sizes[img.name])
        if img.parts:
            data.clear()
            src = _part_dir(root, img)
            for part in img.parts:
                chunk = bytearray((src / part.name).read_bytes())
                _sign_part(chunk, part, keys, rb)
                data.extend(chunk)
        if img.stage == "st2":
            if img.key is None:
                raise ValueError(f"missing key mode for {img.name}")
            cs.sign_st2(data, keys, img.key, False, rb)
        images[img.name] = bytes(data)

    updates = {}
    for img in IMAGES:
        if img.avb is None:
            continue
        data = bytearray(images[img.name])
        updates[img.avb] = avb.wrap(data, keys.avb, keys.avb_pub, img.avb)
        images[img.name] = bytes(data)

    vbmeta = _read(root, BY_NAME["vbmeta.img"], sizes["vbmeta.img"])
    avb.update_top(vbmeta, keys.avb, keys.avb_pub, updates)
    cs.sign_st2(vbmeta, keys, "ree", False, rb)
    images["vbmeta.img"] = bytes(vbmeta)
    return images


def sign_images(stock: dict[str, bytes], keys: cs.Keys,
                rb: int | None = None) -> tuple[dict[str, bytes], dict]:
    with tempfile.TemporaryDirectory(prefix="s5e8825-sign-") as tmp:
        work = Path(tmp) / "work"
        _write(stock, work, Path("stock"))
        images = _build(work, keys, rb)
    return images, check(images, keys)


def _mode(img: Image, part: Part | None = None) -> str:
    item = part or img
    if item.stage is None:
        return "unsigned"
    if item.stage == "st1":
        return "CodeSigner v5 ST1"
    return f"CodeSigner v5 ST2 {item.key.upper()}"


def check(images: dict[str, bytes], keys: cs.Keys | None = None) -> dict:
    _check(images)
    fld = images["fld.bin"]
    stock_tee, stock_ree = cs.stock_keys(fld)
    tee = keys.tee.public_key() if keys else stock_tee
    ree = keys.ree.public_key() if keys else stock_ree
    info = {"version": fw_version(images), "images": {}}
    updates = {}

    for img in IMAGES:
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
                rec.update(cs.verify_st1(raw, keys))
            elif part.stage == "st2":
                pub = tee if part.key == "tee" else ree
                rec.update(cs.verify_st2(raw, pub, part.key or "", part.header))
                _check_index(rec, keys, part.key or "")
            if part.avb_keys and keys is not None:
                check = bytearray(raw)
                rec["avb_key_offsets"] = [f"{off:#x}" for off in cs.replace_avb_keys(check, keys.avb_pub)]
                if check != raw:
                    raise ValueError("keystorage AVB keys were not replaced")
            item["parts"].append(rec)
        if img.stage == "st2":
            item.update(cs.verify_st2(data, ree if img.key == "ree" else tee, img.key or ""))
            _check_index(item, keys, img.key or "")
        if img.name == "vbmeta.img":
            item.update(cs.verify_st2(data, ree, "ree"))
            _check_index(item, keys, "ree")
        if img.avb:
            pub = keys.avb_pub if keys else None
            updates[img.avb] = avb.verify_wrap(data, pub, img.avb)
            item["avb"] = "SHA256_RSA4096"
        info["images"][img.name] = item

    vbmeta = images["vbmeta.img"]
    top_pub = keys.avb_pub if keys else avb.public(vbmeta)
    avb.verify_top(vbmeta, top_pub, updates)
    info["images"]["vbmeta.img"]["avb"] = "SHA256_RSA4096"
    info["ok"] = True
    return info


def _tar(images: dict[str, bytes], path: Path, tar_name: str | None = None) -> None:
    tar_name = tar_name or path.name.removesuffix(".md5")
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
        for img in IMAGES:
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


def write_tar(images: dict[str, bytes], path: Path,
              tar_name: str | None = None) -> None:
    _tar(images, path, tar_name)


def build(work: Path, key_dir: Path, out: Path, rb: int | None) -> None:
    if not (work / "layout.json").is_file():
        raise ValueError("work directory was not prepared by this signer")
    keys = cs.Keys.load(key_dir)
    images = _build(work, keys, rb)
    info = check(images, keys)
    _empty(out)
    raw = out / "images"
    raw.mkdir()
    for img in IMAGES:
        (raw / img.name).write_bytes(images[img.name])
    (out / "check.json").write_text(json.dumps(info, indent=2) + "\n")
    archive = out / f"BL_{fw_version(images)}_CUSTOM.tar.md5"
    _tar(images, archive)
    print(archive)


def load_images(path: Path) -> dict[str, bytes]:
    root = path / "images" if (path / "images").is_dir() else path
    return {img.name: (root / img.name).read_bytes() for img in IMAGES}


def run_check(path: Path, key_path: Path | None) -> None:
    keys = cs.Keys.load(key_path) if key_path else None
    print(json.dumps(check(load_images(path), keys), indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(prog="s5e8825-signer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("source", type=Path)
    prep.add_argument("work", type=Path)
    make = sub.add_parser("build")
    make.add_argument("work", type=Path)
    make.add_argument("keys", type=Path)
    make.add_argument("output", type=Path)
    make.add_argument("--rollback", type=lambda val: int(val, 0))
    chk = sub.add_parser("check")
    chk.add_argument("images", type=Path)
    chk.add_argument("--keys", type=Path)
    a = ap.parse_args()
    if a.cmd == "prepare":
        prepare(a.source, a.work)
    elif a.cmd == "build":
        build(a.work, a.keys, a.output, a.rollback)
    else:
        run_check(a.images, a.keys)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"error: {exc}")
