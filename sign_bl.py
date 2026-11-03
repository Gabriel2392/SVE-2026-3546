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
import signer
from layout import BY_NAME, KEY_IMAGE, LK_IMAGE, LK_PART, SIGNING_TYPE


OLD_TAG = b"Samsung Official"
NEW_TAG = b" Rakesh Official"


def patch_lk(images: dict[str, bytes]) -> dict[str, bytes]:
    part = next(item for item in BY_NAME[LK_IMAGE].parts if item.name == LK_PART)
    data = bytearray(images[LK_IMAGE])
    raw = bytes(data[part.start:part.end])
    data[part.start:part.end] = raw.replace(OLD_TAG, NEW_TAG)
    out = dict(images)
    out[LK_IMAGE] = bytes(data)
    return out


def key_path(path: Path | None) -> Path:
    if path is not None:
        return path.resolve()
    env = os.environ.get("S5E8825_KEYS")
    paths = ([Path(env)] if env else []) + [ROOT / "signer" / "keys"]
    for path in paths:
        if (path / "4" / "st1.pem").is_file() and (path / "avb.pem").is_file():
            return path.resolve()
    raise ValueError("signing keys not found; set S5E8825_KEYS or use --keys")


def out_path(path: Path, suffix: str) -> Path:
    name = path.name
    if name.endswith(".tar.md5"):
        return path.with_name(f"{name[:-8]}{suffix}.tar.md5")
    return path.with_name(f"{path.stem}{suffix}{path.suffix}")


def sign_pit(data: bytes, ree, keys: cs.Keys, rb: int | None, fw: str) -> bytes:
    if len(data) < 0x310 or data[:4] != struct.pack("<I", 0x12349876):
        raise ValueError("invalid PIT header")
    count = struct.unpack_from("<I", data, 4)[0]
    end = 0x1C + count * 0x84
    if not 0 < count <= 128 or end + 0x310 != len(data):
        raise ValueError("invalid PIT layout")
    info = len(data) - 0x310
    if data[info:info + 11] != b"SignerVer03":
        raise ValueError("PIT has no CodeSigner metadata")
    pit_fw = data[info + 32:info + 64].split(b"\0", 1)[0].decode("ascii")
    if pit_fw != fw:
        raise ValueError(f"BL/PIT mismatch: {fw} / {pit_fw}")
    cs.verify_st2(data, ree, "ree", False, SIGNING_TYPE)
    out = bytearray(data)
    cs.sign_st2(out, keys, "ree", False, rb, SIGNING_TYPE)
    cs.verify_st2(out, keys.ree.public_key(), "ree", False, SIGNING_TYPE)
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

    keys = cs.Keys.load(key_path(a.keys))
    stock = signer.load_stock(bl)
    fw = signer.fw_version(stock)
    _, ree = cs.stock_keys(stock[KEY_IMAGE], SIGNING_TYPE)
    pit_data = sign_pit(pit.read_bytes(), ree, keys, a.rollback, fw)
    stock = patch_lk(stock)
    images, _ = signer.sign_images(stock, keys, a.rollback)

    bl_tmp = temp(bl_out)
    pit_tmp = temp(pit_out)
    try:
        signer.write_tar(images, bl_tmp, bl_out.name.removesuffix(".md5"))
        pit_tmp.write_bytes(pit_data)
        os.replace(bl_tmp, bl_out)
        os.replace(pit_tmp, pit_out)
    finally:
        bl_tmp.unlink(missing_ok=True)
        pit_tmp.unlink(missing_ok=True)

    print(bl_out)
    print(pit_out)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"error: {exc}")
