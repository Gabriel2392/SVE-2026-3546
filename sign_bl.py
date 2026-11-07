#!/usr/bin/env python3
import argparse
import os
import struct
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "signer"))

import cs
import patches
import signer
from layout import SOCS, Layout


def patch_lk(images: dict[str, bytes], layout: Layout) -> tuple[dict[str, bytes], int | None]:
    image = layout.by_name[layout.lk_image]
    part = next(item for item in image.parts if item.name == layout.lk_part)
    data = bytearray(images[layout.lk_image])
    raw, d2 = patches.patch_lk(bytes(data[part.start:part.end]))
    data[part.start:part.end] = raw
    out = dict(images)
    out[layout.lk_image] = bytes(data)
    return out, d2


def key_path(path: Path | None, layout: Layout) -> Path:
    if path is not None:
        return path.resolve()
    env = os.environ.get(f"{layout.soc.upper()}_KEYS") or os.environ.get("EXYNOS_KEYS")
    paths = ([Path(env)] if env else []) + [ROOT / "signer" / "keys"]
    for path in paths:
        if (path / "4" / "st1.pem").is_file() and (path / "avb.pem").is_file():
            return path.resolve()
    raise ValueError("signing keys not found; set EXYNOS_KEYS or use --keys")


def out_path(path: Path, suffix: str) -> Path:
    name = path.name
    if name.endswith(".tar.md5"):
        return path.with_name(f"{name[:-8]}{suffix}.tar.md5")
    if name.endswith(".tar"):
        return path.with_name(f"{name[:-4]}{suffix}.tar.md5")
    return path.with_name(f"{path.stem}{suffix}{path.suffix}")


def sign_pit(data: bytes, stock: dict[str, bytes], layout: Layout,
             ree, keys: cs.Keys, rb: int | None) -> bytes:
    if len(data) < 0x310 or data[:4] != struct.pack("<I", 0x12349876):
        raise ValueError("invalid PIT header")
    count = struct.unpack_from("<I", data, 4)[0]
    end = 0x1C + count * 0x84
    if not 0 < count <= 128 or end + 0x310 != len(data):
        raise ValueError("invalid PIT layout")
    bl_id = cs.signer_info(stock[layout.key_image])
    pit_id = cs.signer_info(data)
    if (pit_id["product"], pit_id["keyset"]) != (
            bl_id["product"], bl_id["keyset"]):
        raise ValueError("BL/PIT product identity mismatch")

    entries = []
    for index in range(count):
        off = 0x1C + index * 0x84
        raw = data[off:off + 0x84]
        words = struct.unpack_from("<9I", raw)
        name = raw[0x44:0x64].split(b"\0", 1)[0].decode("ascii")
        entries.append((name, words[1], words[6]))
    for image in (item for item in layout.images if item.bundle):
        found = [item for item in entries if item[0] == image.name]
        if len(found) != 1 or found[0][1] != 8 or not found[0][2]:
            raise ValueError(f"invalid PIT mapping for {image.name}")
        if len(stock[image.name]) > found[0][2] * 0x1000:
            raise ValueError(f"{image.name} exceeds its PIT partition")

    cs.verify_st2(data, ree, "ree", False, layout.signing_type)
    out = bytearray(data)
    cs.sign_st2(out, keys, "ree", False, rb, layout.signing_type)
    cs.verify_st2(out, keys.ree.public_key(), "ree", False, layout.signing_type)
    return bytes(out)


def temp(dst: Path) -> Path:
    fd, name = tempfile.mkstemp(prefix=f".{dst.name}.", dir=dst.parent)
    os.close(fd)
    return Path(name)


def main() -> None:
    ap = argparse.ArgumentParser(prog="sign_bl.py")
    ap.add_argument("bl", type=Path)
    ap.add_argument("pit", type=Path)
    ap.add_argument("--keys", type=Path)
    ap.add_argument("--soc", required=True, choices=SOCS)
    ap.add_argument("--rollback", type=lambda val: int(val, 0))
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    bl = a.bl.resolve()
    pit = a.pit.resolve()
    if not bl.is_file() or not pit.is_file():
        raise ValueError("BL and PIT must be files")
    bl_out = out_path(bl, "_RESIGNED")
    pit_out = out_path(pit, "_RESIGNED")
    if not a.force and (bl_out.exists() or pit_out.exists()):
        raise ValueError("output exists; use --force to replace it")

    layout, stock = signer.load_stock(bl, a.soc)
    keys = cs.Keys.load(key_path(a.keys, layout))
    _, ree = cs.stock_keys(stock[layout.key_image], layout.signing_type)
    pit_data = sign_pit(pit.read_bytes(), stock, layout, ree, keys, a.rollback)
    stock, d2 = patch_lk(stock, layout)
    images, _ = signer.sign_images(stock, layout, keys, a.rollback)
    patches.check_lk(layout.lk(images), d2)

    bl_tmp = temp(bl_out)
    pit_tmp = temp(pit_out)
    try:
        signer.write_tar(
            images, layout, bl_tmp, bl_out.name.removesuffix(".md5")
        )
        check_layout, check_images = signer.load_stock(bl_tmp, a.soc)
        patches.check_lk(check_layout.lk(check_images), d2)
        pit_tmp.write_bytes(pit_data)
        os.replace(bl_tmp, bl_out)
        os.replace(pit_tmp, pit_out)
    finally:
        bl_tmp.unlink(missing_ok=True)
        pit_tmp.unlink(missing_ok=True)

    print("D2: absent" if d2 is None else f"D2: LK+{d2:#x}")
    print(f"{layout.soc}: {bl_out}")
    print(pit_out)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"error: {exc}")
