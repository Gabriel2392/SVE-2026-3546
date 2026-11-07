import struct


OLD_TAG = b"Samsung Official"
NEW_TAG = b" Rakesh Official"
NOP = 0xD503201F
DISPLAY = b"display_dmc_screen\0"
READER = b"read_dmc_rpmb\0"
INPUT = b"check_otp_input\0"
D2_SIG = (
    DISPLAY,
    INPUT,
    b"PO_DMC\0",
    b"[Reboot Device - %s]\n\0",
    b"Volume Down + Power key for 7 seconds\n\0",
)


def u32(data, at):
    if at < 0 or at + 4 > len(data):
        raise ValueError("D2 layout")
    return struct.unpack_from("<I", data, at)[0]


def find_all(data, value):
    out = []
    at = 0
    while True:
        at = data.find(value, at)
        if at < 0:
            return out
        out.append(at)
        at += 1


def one(values):
    if len(values) != 1:
        raise ValueError("D2 layout")
    return values[0]


def adrp(insn, pc):
    if insn & 0x9F000000 != 0x90000000:
        return None
    value = ((insn >> 29) & 3) | (((insn >> 5) & 0x7FFFF) << 2)
    if value & (1 << 20):
        value -= 1 << 21
    return (pc & ~0xFFF) + (value << 12), insn & 31


def add(insn):
    if insn & 0xFF000000 != 0x91000000:
        return None
    value = (insn >> 10) & 0xFFF
    if insn >> 22 & 1:
        value <<= 12
    return value, insn & 31, insn >> 5 & 31


def refs(data, target):
    out = []
    for at in range(0, len(data) - 4, 4):
        first = adrp(u32(data, at), at)
        if first is None:
            continue
        page, reg = first
        for pos in range(at + 4, min(at + 0x14, len(data) - 3), 4):
            second = add(u32(data, pos))
            if second is not None and second[2] == reg and page + second[0] == target:
                out.append((at, pos))
                break
    return out


def is_frame(data, at):
    return (at + 8 <= len(data) and u32(data, at) & 0xFFC07FFF == 0xA9807BFD
            and any(u32(data, pos) & 0xFFC003FF == 0x910003FD
                    for pos in range(at + 4, min(at + 0x28, len(data) - 3), 4)))


def frame(data, ref):
    for at in range(ref & ~3, -1, -4):
        if is_frame(data, at):
            return at
    raise ValueError("D2 layout")


def next_frame(data, start):
    for at in range(start + 4, len(data) - 7, 4):
        if is_frame(data, at):
            return at
    raise ValueError("D2 layout")


def named(data, name):
    string = one(find_all(data, name))
    found = refs(data, string)
    if not found:
        raise ValueError("D2 layout")
    return one(sorted({frame(data, ref) for ref, _ in found}))


def call(data, at):
    insn = u32(data, at)
    if insn & 0xFC000000 != 0x94000000:
        return None
    value = insn & 0x3FFFFFF
    if value & 0x2000000:
        value -= 0x4000000
    return at + (value << 2)


def callers(data, target, start=0, end=None):
    end = len(data) if end is None else min(end, len(data))
    return [at for at in range(start, end - 3, 4) if call(data, at) == target]


def movz(insn):
    if insn >> 31 or insn & 0x7F800000 != 0x52800000:
        return None
    shift = (insn >> 21) & 3
    if shift > 1:
        return None
    return ((insn >> 5) & 0xFFFF) << (shift * 16), insn & 31


def download(data, at, display):
    if at < 0x1C or at + 0x18 > len(data) or movz(u32(data, at - 4)) != (1, 0):
        return None
    word = u32(data, at)
    if word == NOP:
        done = True
    elif call(data, at) == display:
        done = False
    else:
        return None
    if movz(u32(data, at + 4)) != (0x20000, 0) or movz(u32(data, at + 8)) != (1, 1):
        return None
    targets = (call(data, at + 12), call(data, at + 20))
    if any(target is None or not 0 <= target < len(data) for target in targets):
        return None
    start = at - 0x1C
    if (u32(data, start) & 0xFFC003FF != 0xD10003FF
            or u32(data, start + 4) & 0xFFC07FFF != 0xA9007BFD
            or any(u32(data, start + pos) & 0xFFC003E0 != 0xA90003E0 for pos in (8, 12))
            or u32(data, start + 16) & 0xFFC003FF != 0x910003FD):
        return None
    save = u32(data, start + 20)
    restore = u32(data, at + 16)
    if (save & 0xFFFFFFE0 != 0x2A0003E0 or restore & 0xFFE0FFFF != 0x2A0003E0
            or (restore >> 16) & 31 != save & 31):
        return None
    return done


def d2(data):
    counts = [len(find_all(data, marker)) for marker in D2_SIG]
    if not any(counts):
        return None
    if any(count != 1 for count in counts) or len(find_all(data, READER)) != 1:
        raise ValueError("D2 layout")
    display = named(data, DISPLAY)
    reader = named(data, READER)
    handler = named(data, INPUT)
    end = next_frame(data, display)
    if len(callers(data, reader, display, end)) != 2 or len(callers(data, handler, display, end)) != 1:
        raise ValueError("D2 layout")
    volume = one(find_all(data, D2_SIG[-1]))
    if sum(display <= at < end for at, _ in refs(data, volume)) != 1:
        raise ValueError("D2 layout")
    direct = callers(data, display)
    upload = [at for at in direct if at >= 4 and u32(data, at - 4) == 0x2A1F03E0]
    found = []
    for at in range(0x1C, len(data) - 0x18, 4):
        state = download(data, at, display)
        if state is not None:
            found.append((at, state))
    at, done = one(found)
    expected = {one(upload)} if done else {one(upload), at}
    if set(direct) != expected:
        raise ValueError("D2 layout")
    return at, done


def patch_lk(data):
    out = bytearray(data.replace(OLD_TAG, NEW_TAG))
    found = d2(out)
    if found is None:
        return bytes(out), None
    at, done = found
    if not done:
        before = bytes(out)
        struct.pack_into("<I", out, at, NOP)
        if before[:at] != out[:at] or before[at + 4:] != out[at + 4:]:
            raise ValueError("D2 patch")
    if d2(out) != (at, True):
        raise ValueError("D2 patch")
    return bytes(out), at


def check_lk(data, at):
    found = d2(data)
    if at is None:
        if found is not None:
            raise ValueError("D2 patch")
    elif found != (at, True):
        raise ValueError("D2 patch")
