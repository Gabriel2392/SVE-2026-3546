#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import lzma
import struct
import sys
import tarfile
from pathlib import Path

import lz4.frame


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "signer"))
from layout import IMAGES, KEY_IMAGE, SIGNING_TYPE


MAGIC = 0x42333541
VERSION = 1
HEADER = struct.Struct("<IHH6I32s")
ENTRY = struct.Struct("<32sIIII32s48s")
PIT_MAGIC = 0x12349876
PIT_HEADER = 0x1C
PIT_ENTRY = 0x84
FILES = tuple(image.name for image in IMAGES if image.bundle)
ALL_FILES = tuple(image.name for image in IMAGES)
DICT_SIZE = 1 << 21


def align(value: int, size: int = 16) -> int:
    return (value + size - 1) & -size


def cstr(value: str) -> bytes:
    data = value.encode("ascii")
    if not data or len(data) >= 32:
        raise ValueError(f"invalid bundle name: {value}")
    return data.ljust(32, b"\0")


def load(path: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(path, "r:*") as tar:
        items = {item.name: item for item in tar.getmembers() if item.isfile()}
        for name in ALL_FILES:
            item = items.get(f"{name}.lz4")
            if item is None:
                raise ValueError(f"missing {name}.lz4")
            src = tar.extractfile(item)
            if src is None:
                raise ValueError(f"cannot read {name}.lz4")
            out[name] = lz4.frame.decompress(src.read())
    return out


def read_pit(data: bytes) -> list[dict]:
    if len(data) < PIT_HEADER or struct.unpack_from("<I", data)[0] != PIT_MAGIC:
        raise ValueError("invalid PIT")
    count = struct.unpack_from("<I", data, 4)[0]
    end = PIT_HEADER + count * PIT_ENTRY
    if not 0 < count <= 128 or end + 0x310 != len(data):
        raise ValueError("invalid signed PIT layout")
    out = []
    for index in range(count):
        raw = data[PIT_HEADER + index * PIT_ENTRY:PIT_HEADER + (index + 1) * PIT_ENTRY]
        words = struct.unpack_from("<9I", raw)
        text = [raw[off:off + 32].split(b"\0", 1)[0].decode("ascii")
                for off in (0x24, 0x44, 0x64)]
        out.append({
            "name": text[0],
            "file": text[1],
            "device": words[1],
            "start": words[5],
            "blocks": words[6],
            "lun": words[7],
        })
    return out


def part(entries: list[dict], name: str, pit: bool = False) -> dict:
    if pit:
        found = [item for item in entries if item["name"] == "PIT"]
    else:
        found = [item for item in entries if item["file"] == name]
    if len(found) != 1:
        raise ValueError(f"PIT map {name}: {len(found)}")
    item = found[0]
    if item["device"] != 8 or item["blocks"] == 0 or item["lun"] > 7:
        raise ValueError(f"unsupported PIT mapping for {name}")
    return item


def load_py(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("bl", type=Path)
    ap.add_argument("pit", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("header", type=Path)
    a = ap.parse_args()

    root = ROOT
    import cs
    import signer

    imgs = load(a.bl)
    signer.check(imgs)
    pit = a.pit.read_bytes()
    _, ree = cs.stock_keys(imgs[KEY_IMAGE], SIGNING_TYPE)
    cs.verify_st2(pit, ree, "ree", False, SIGNING_TYPE)
    parts = read_pit(pit)
    src = [(name, imgs[name], 0) for name in FILES]
    src.append((a.pit.name, pit, 1))

    filt = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": DICT_SIZE,
        "lc": 3,
        "lp": 0,
        "pb": 2,
        "mode": lzma.MODE_NORMAL,
        "nice_len": 64,
        "mf": lzma.MF_BT4,
    }]
    packs = []
    for name, raw, flags in src:
        dst = part(parts, name, bool(flags))
        if len(raw) > dst["blocks"] * 0x1000:
            raise ValueError(f"{name} exceeds its PIT partition")
        blob = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filt)
        packs.append((name, raw, blob, flags))

    data_off = align(HEADER.size + len(packs) * ENTRY.size, 0x1000)
    off = data_off
    recs = []
    body = bytearray(data_off - HEADER.size)
    for name, raw, blob, flags in packs:
        off = align(off)
        if len(body) < off - HEADER.size:
            body.extend(bytes(off - HEADER.size - len(body)))
        recs.append(ENTRY.pack(
            cstr(name), off, len(blob), len(raw), flags,
            hashlib.sha256(raw).digest(), bytes(48),
        ))
        body.extend(blob)
        off += len(blob)
    for index, rec in enumerate(recs):
        pos = index * ENTRY.size
        body[pos:pos + ENTRY.size] = rec
    total = HEADER.size + len(body)
    pit_i = len(packs) - 1
    digest = hashlib.sha256(body).digest()
    hdr = HEADER.pack(
        MAGIC, VERSION, HEADER.size, total, len(packs), ENTRY.size,
        data_off, pit_i, DICT_SIZE, digest,
    )
    data = hdr + body

    cfg = load_py(root / "offsets.py", "s5e8825_offsets")
    if len(data) > cfg.PACK_MAX:
        raise ValueError("bundle too large")
    a.out.write_bytes(data)
    a.header.write_text(
        "#pragma once\n"
        f"#define BUNDLE_EXPECTED_COUNT {len(packs)}U\n"
        f"#define BUNDLE_PIT_INDEX {pit_i}U\n"
        f"#define BUNDLE_DICTIONARY_SIZE {DICT_SIZE:#x}U\n"
        f"#define BUNDLE_SIZE {len(data):#x}U\n"
    )
    print(f"{a.out} {len(data):#x} free={cfg.PACK_MAX - len(data):#x}")


if __name__ == "__main__":
    main()
