#!/usr/bin/env python3
import argparse
import hashlib
import struct
import sys
import time
from pathlib import Path

import usb.core
import usb.util

sys.dont_write_bytecode = True

from offsets import (
    BLOCK,
    CB_OFF,
    CODE_ADDR,
    CODE_MAX,
    CODE_OFF,
    CODE_STORE_ADDR,
    CODE_SLOT,
    CONTEXT_ADDR,
    CONTEXT_RESTORE,
    CTL_LEN,
    MMU_DISABLE,
    MMU_ENABLE,
    PACK_ADDR,
    PACK_MAX,
    PACK_SLOT,
    PAR_SLOT,
    REPLY_ADDR,
    RESERVE,
    RESULT_OK,
    SOC,
    STACK_ADDR,
    STAGE_ADDR,
    STAGE_STORE_ADDR,
    PTE_ADDR,
    PTE_VALUE,
    WALK_LEN,
    WRITE_ADDR,
)

ROOT = Path(__file__).resolve().parent
PIT_ENT = 0x84


def pkt(op, sub=0, args=()):
    vals = [op, sub, *args]
    return struct.pack("<256I", *(vals + [0] * (256 - len(vals))))


def rx(dev, size, timeout=30000):
    data = bytes(dev.read(0x81, size, timeout=timeout))
    if len(data) != size:
        raise RuntimeError(f"short read {len(data):#x}/{size:#x}")
    return data


def tx(dev, data, timeout=30000):
    if dev.write(0x01, data, timeout=timeout) != len(data):
        raise RuntimeError("short write")


def cmd(dev, op, sub=0, args=(), timeout=30000):
    tx(dev, pkt(op, sub, args), timeout)
    req, ret = struct.unpack("<II", rx(dev, 8, timeout))
    if req != op:
        raise RuntimeError(f"odin {op}:{sub}")
    return ret


def open_usb():
    dev = usb.core.find(idVendor=0x04E8, idProduct=0x685D)
    if dev is None:
        raise RuntimeError("device not found")
    try:
        if dev.is_kernel_driver_active(1):
            dev.detach_kernel_driver(1)
    except (NotImplementedError, usb.core.USBError):
        pass
    usb.util.claim_interface(dev, 1)
    return dev


def get_pit(dev):
    size = cmd(dev, 101, 1)
    if not 0x1C <= size <= 0x4000:
        raise RuntimeError(f"PIT size {size:#x}")
    out = bytearray()
    for index, off in enumerate(range(0, size, 500)):
        tx(dev, pkt(101, 2, (index,)))
        out += rx(dev, min(500, size - off))
    return bytes(out)


def part(pit, name):
    if struct.unpack_from("<I", pit)[0] != 0x12349876:
        raise RuntimeError("bad PIT")
    for index in range(struct.unpack_from("<I", pit, 4)[0]):
        off = 0x1C + index * PIT_ENT
        ent = pit[off:off + PIT_ENT]
        if ent[0x24:0x44].split(b"\0", 1)[0] == name:
            return struct.unpack_from("<II", ent, 4)
    raise RuntimeError(f"missing {name.decode()}")


def send_data(dev, size, head=b"", step=BLOCK):
    zero = bytes(step)
    total = (size + step - 1) // step * step
    for off in range(0, total, step):
        block = zero
        if off < len(head):
            block = bytearray(zero)
            n = min(step, len(head) - off)
            block[:n] = head[off:off + n]
        tx(dev, block)
        rx(dev, 8)


def put(dev, size, dst, last, head=b""):
    cmd(dev, 102, 2, (size,))
    send_data(dev, size, head)
    cmd(dev, 102, 3, (0, size, 0, dst[0], dst[1], last))


def put_comp(dev, size, dst, data=None, timeout=30000):
    data = bytes(4) if data is None else data
    if len(data) < size and len(data) != 4:
        raise RuntimeError("short compressed block")
    raw = struct.pack("<I", size | 0x80000000) + data
    cmd(dev, 102, 6, (len(raw),))
    send_data(dev, len(raw), raw, 8)
    return cmd(dev, 102, 7, (0, 8, 0, dst[0], dst[1], 0), timeout)


def load_bundle(path):
    data = path.read_bytes()
    if not 64 <= len(data) <= PACK_MAX:
        raise RuntimeError("bundle size")
    hdr = struct.unpack_from("<IHH6I32s", data)
    if hdr[:4] != (0x42333541, 1, 64, len(data)):
        raise RuntimeError("bundle header")
    if hashlib.sha256(data[64:]).digest() != hdr[-1]:
        raise RuntimeError("bundle hash")
    if RESERVE + len(data) > PAR_SLOT:
        raise RuntimeError("bundle slot")
    return data


def invoke(dev, dst, target, reply, timeout=30000):
    ctl = bytearray(CTL_LEN)
    struct.pack_into("<Q", ctl, 0, reply)
    struct.pack_into("<Q", ctl, CB_OFF, target)
    return put_comp(dev, len(ctl), dst, bytes(ctl), timeout)


def branch(pc, target, link=False):
    delta = target - pc
    if delta & 3 or not -(1 << 27) <= delta < 1 << 27:
        raise RuntimeError("stage branch")
    return (0x94000000 if link else 0x14000000) | (delta >> 2 & 0x3FFFFFF)


def literal(pc, target, reg):
    delta = target - pc
    if delta & 3 or not -(1 << 20) <= delta < 1 << 20:
        raise RuntimeError("stage literal")
    return 0x58000000 | (delta >> 2 & 0x7FFFF) << 5 | reg


def stage_code():
    lit = STAGE_STORE_ADDR + 0x48
    words = [
        literal(STAGE_STORE_ADDR, lit, 9),
        0xD5087629,
        0xD5033F9F,
        literal(STAGE_STORE_ADDR + 0xC, lit + 8, 10),
        0xF900012A,
        0xD5033F9F,
        0xD508871F,
        0xD5033F9F,
        0xD5033FDF,
        literal(STAGE_STORE_ADDR + 0x24, lit + 16, 30),
        literal(STAGE_STORE_ADDR + 0x28, lit + 24, 16),
        0xD61F0200,
        literal(STAGE_ADDR + 0x30, STAGE_ADDR + 0x68, 0),
        0x52800101,
        branch(STAGE_ADDR + 0x38, CODE_ADDR, True),
        0xD503205F,
        branch(STAGE_ADDR + 0x40, STAGE_ADDR + 0x3C),
        0xD503201F,
    ]
    data = bytearray(struct.pack(f"<{len(words)}I", *words))
    data += struct.pack(
        "<5Q", PTE_ADDR, PTE_VALUE, STAGE_ADDR + 0x30,
        MMU_ENABLE, REPLY_ADDR,
    )
    return bytes(data)


def context():
    data = bytearray(0x110)
    struct.pack_into("<4Q", data, 0xF0, STAGE_STORE_ADDR,
                     STACK_ADDR, MMU_DISABLE, 0x3C5)
    return bytes(data)


def walk(dev, dst, left, done, total, mark):
    while left:
        size = min(left, BLOCK)
        put_comp(dev, size, dst)
        left -= size
        done += size
        if done >= mark or done == total:
            print(f"walk {done:#x}/{total:#x}", flush=True)
            mark = done + 0x4000000
    return done, mark


def run(code_path, bundle_path):
    code = code_path.read_bytes()
    bundle = load_bundle(bundle_path)
    if not code or len(code) > CODE_MAX or CODE_OFF + len(code) > 0x1000:
        raise RuntimeError("loader size")

    dev = open_usb()
    try:
        print("connect", flush=True)
        tx(dev, b"ODIN")
        if rx(dev, 4) != b"LOKE" or cmd(dev, 100, 0) != 0x00028000:
            raise RuntimeError("handshake")
        cmd(dev, 100, 2, (0x7FFFFFFF,))
        pit = get_pit(dev)
        scratch = part(pit, b"UL_KEYS")
        boot = part(pit, b"BOOT")
        cmd(dev, 100, 5, (BLOCK,))
        cmd(dev, 102, 0)

        print("stage", flush=True)
        reserve = bytearray(RESERVE)
        if CONTEXT_ADDR:
            if CONTEXT_ADDR != PACK_ADDR - RESERVE:
                raise RuntimeError("context address")
            reserve[:0x110] = context()
        for slot in range(CODE_SLOT):
            if slot == PACK_SLOT:
                put(dev, RESERVE + len(bundle), scratch, 0,
                    reserve + bundle)
            else:
                put(dev, 1, scratch, 1)
        staged = bytearray(CODE_OFF + len(code))
        staged[CODE_OFF:] = code
        if STAGE_STORE_ADDR:
            off = CODE_OFF + STAGE_STORE_ADDR - CODE_STORE_ADDR
            transition = stage_code()
            if off < 0 or off + len(transition) > CODE_OFF:
                raise RuntimeError("stage layout")
            staged[off:off + len(transition)] = transition
        put(dev, len(staged), boot, 0, staged)
        put(dev, 1, scratch, 1)

        cmd(dev, 100, 5, (8,))
        cmd(dev, 102, 5)
        walk(dev, scratch, WALK_LEN, 0, WALK_LEN, 0x4000000)

        print(f"trigger {WRITE_ADDR:#x}", flush=True)
        start = time.monotonic()
        target = CONTEXT_RESTORE or CODE_ADDR
        reply = CONTEXT_ADDR or REPLY_ADDR
        ret = invoke(dev, boot, target, reply, 600000)
        if ret != RESULT_OK:
            raise RuntimeError(f"loader {ret:#x}")
        print(f"done {time.monotonic() - start:.1f}s", flush=True)
    finally:
        try:
            usb.util.dispose_resources(dev)
        except usb.core.USBError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--soc", required=True, choices=("s5e8825", "s5e9925"))
    ap.add_argument("code", type=Path, nargs="?", default=ROOT / "loader.bin")
    ap.add_argument("--bundle", type=Path, default=ROOT / "loader/bundle.bin")
    args = ap.parse_args()
    if args.soc != SOC:
        raise ValueError(f"generated loader is for {SOC}, not {args.soc}")
    run(args.code.resolve(), args.bundle.resolve())


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"error: {exc}")
