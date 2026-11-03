#!/usr/bin/env python3
import argparse
import collections
import hashlib
import struct
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
LK_BASE = 0
PAGE_SIZE = 0x1000
CODE_OFFSET = 0x100
CODE_CAPACITY = 0xEE0


def load_lk(path):
    if not path.name.endswith(".tar.md5"):
        return path.read_bytes()
    sys.path.insert(0, str(HERE / "signer"))
    import signer
    from layout import BY_NAME, LK_IMAGE, LK_PART
    images = signer._members(path)
    part = next(item for item in BY_NAME[LK_IMAGE].parts if item.name == LK_PART)
    return images[LK_IMAGE][part.start:part.end]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def find_all(data, pattern):
    matches = []
    start = 0
    while True:
        offset = data.find(pattern, start)
        if offset < 0:
            break
        matches.append(offset)
        start = offset + 1
    return matches


def unique(data, pattern, label):
    matches = find_all(data, pattern)
    if len(matches) != 1:
        raise RuntimeError(f"{label}: {len(matches)} matches")
    return matches[0]


def adrp(insn, pc):
    if insn & 0x9F000000 != 0x90000000:
        raise RuntimeError("expected ADRP")
    imm = ((insn >> 29) & 3) | (((insn >> 5) & 0x7FFFF) << 2)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12), insn & 31


def add_imm(insn):
    if insn & 0xFF000000 != 0x91000000:
        raise RuntimeError("expected ADD immediate")
    val = (insn >> 10) & 0xFFF
    if insn >> 22 & 1:
        val <<= 12
    return val, insn & 31, insn >> 5 & 31


def mov_wide(insn):
    kind = insn & 0x7F800000
    if kind not in (0x52800000, 0x72800000):
        return None
    val = ((insn >> 5) & 0xFFFF) << (16 * ((insn >> 21) & 3))
    return val, insn & 31, insn >> 31, kind


def image_map(data):
    bss = []
    limit = min(len(data), 0x400)
    for offset in range(0, limit - 0x18 + 1, 8):
        start, duplicate, end = struct.unpack_from("<QQQ", data, offset)
        if (start == duplicate and 0x80000000 <= start < 0x1000000000 and
                start % PAGE_SIZE == 0 and start < end and
                end - start < 0x10000000):
            bss.append((start, end))
    if len(bss) != 1:
        raise RuntimeError(f"LK BSS: {bss}")
    bss_start, bss_end = bss[0]

    mappings = []
    for offset in range(0, len(data) - 0x28, 8):
        name, start, end, physical, _ = struct.unpack_from("<5Q", data, offset)
        if (start != physical or start % 0x100000 or
                not start <= bss_start < bss_end <= end or
                not 0 < bss_start - start < 0x1000000):
            continue
        name_offset = name - start
        if not 0 <= name_offset < len(data):
            continue
        name_end = data.find(b"\0", name_offset, min(len(data), name_offset + 0x80))
        if name_end < 0:
            continue
        label = data[name_offset:name_end]
        if label and all(0x20 <= value < 0x7F for value in label):
            mappings.append((start, end, label))
    mappings = sorted(set(mappings))
    if len(mappings) != 1:
        raise RuntimeError(f"LK map: {mappings}")
    return mappings[0][0], mappings[0][1], bss_start, bss_end


def refs(data, target):
    found = []
    for offset in range(0, len(data) - 0x24, 4):
        insn = u32(data, offset)
        if insn & 0x9F000000 != 0x90000000:
            continue
        page, reg = adrp(insn, LK_BASE + offset)
        for second in range(offset + 4, offset + 0x24, 4):
            add = u32(data, second)
            if add & 0xFF000000 != 0x91000000:
                continue
            val, dst, src = add_imm(add)
            if src == reg and page + val == target:
                found.append((offset, second, dst))
                break
    return found


def str_refs(data, value):
    found = []
    for offset in find_all(data, value + b"\0"):
        found.extend(refs(data, LK_BASE + offset))
    found = sorted(set(found))
    if not found:
        raise RuntimeError(f"{value.decode()} XREF not found")
    return found


def parallel(data):
    candidates = []
    for ref, _, _ in str_refs(data, b"parallel_download_init"):
        start, end = max(0, ref - 0x30), min(len(data), ref + 0x80)
        items = []
        for offset in range(start, end, 4):
            value = mov_wide(u32(data, offset))
            if value and value[3] == 0x52800000:
                items.append((offset, *value))
        for base in items:
            if base[2:] != (0, 0, 0x52800000):
                continue
            for total in items:
                if total[2:] != (2, 0, 0x52800000):
                    continue
                for slot in items:
                    if slot[2:] != (9, 0, 0x52800000):
                        continue
                    span = max(base[0], total[0], slot[0]) - min(base[0], total[0], slot[0])
                    if (span <= 0x20 and slot[1] and total[1] // slot[1] >= 2 and
                            total[1] >= slot[1] * (total[1] // slot[1])):
                        candidates.append((base[1], total[1], slot[1]))
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RuntimeError(f"parallel layout: {candidates}")
    return candidates[0]


def named_fn(data, value, vtable_offset):
    prologue = (0xA9BD7BFD, 0xA90157F6, 0xA9024FF4, 0x910003FD)
    starts = set()
    for ref, _, _ in str_refs(data, value):
        found = []
        for offset in range(ref, max(-1, ref - 0x200), -4):
            if offset + 0x10 <= len(data):
                words = tuple(u32(data, offset + index * 4) for index in range(4))
                if words == prologue:
                    found.append(offset)
                    break
        if len(found) != 1:
            raise RuntimeError(f"{value.decode()} prologue")
        starts.add(found[0])
    if len(starts) != 1:
        raise RuntimeError(f"{value.decode()} funcs: {starts}")
    start = starts.pop()
    load = 0xF9400008 | ((vtable_offset // 8) << 10)
    body = [u32(data, offset) for offset in range(start, min(len(data), start + 0x100), 4)]
    if load not in body or 0xD63F0100 not in body:
        raise RuntimeError(f"{value.decode()} vtable")
    return LK_BASE + start


def io_shift(data, target):
    calls = []
    for off in range(0, len(data) - 4, 4):
        insn = u32(data, off)
        if insn & 0xFC000000 != 0x94000000:
            continue
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        if LK_BASE + off + imm * 4 == target:
            calls.append(off)
    shifts = collections.Counter()
    for call in calls:
        for off in range(max(0, call - 0x100), min(len(data) - 4, call + 0x40), 4):
            insn = u32(data, off)
            if insn & 0x7F800000 != 0x53000000:
                continue
            shift = (insn >> 16) & 0x3F
            if (insn >> 10) & 0x3F == 31 and 6 <= shift <= 16:
                shifts[shift] += 1
    if not shifts:
        raise RuntimeError("block shift")
    shift, count = shifts.most_common(1)[0]
    if count < 3 or list(shifts.values()).count(count) != 1:
        raise RuntimeError(f"block shift {shifts}")
    return shift


def sha256_fn(data):
    prefix = (
        0xA9BF7BFD,
        0x910003FD,
        0xAA0203E3,
        0x2A0103E1,
        0x52800022,
    )
    starts = []
    name_refs = {item[0] for item in str_refs(data, b"em_crypto_sha256")}
    for ref in name_refs:
        for start in range(ref, max(-1, ref - 0x80), -4):
            if start + 0x18 > len(data):
                continue
            words = tuple(u32(data, start + index * 4) for index in range(5))
            if words != prefix:
                continue
            call = u32(data, start + 0x14)
            if call & 0xFC000000 != 0x94000000:
                continue
            starts.append(start)
    starts = sorted(set(starts))
    if len(starts) != 1:
        raise RuntimeError(f"SHA-256 func: {starts}")
    start = starts[0]
    calls = 0
    target = LK_BASE + start
    for off in range(0, len(data) - 4, 4):
        insn = u32(data, off)
        if insn & 0xFC000000 != 0x94000000:
            continue
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        if LK_BASE + off + imm * 4 == target:
            calls += 1
    if calls < 2:
        raise RuntimeError("SHA-256 XREF not found")
    return target


def input_map(data):
    candidates = []
    for ref, _, _ in str_refs(data, b"compressed_download_init"):
        start, end = max(0, ref - 0x20), min(len(data), ref + 0x90)
        bases = []
        for offset in range(start, end, 4):
            first = mov_wide(u32(data, offset))
            if not first or first[1:] != (0, 1, 0x52800000):
                continue
            for second_offset in range(offset + 4, min(offset + 0x24, end), 4):
                second = mov_wide(u32(data, second_offset))
                if second and second[1:] == (0, 1, 0x72800000):
                    bases.append((offset, first[0] | second[0]))
        items = []
        for offset in range(start, end, 4):
            decoded = mov_wide(u32(data, offset))
            if decoded and decoded[3] == 0x52800000:
                items.append((offset, *decoded))
        for base_offset, base in bases:
            if base <= 0xFFFFFFFF:
                continue
            for total in items:
                if total[2:] != (2, 0, 0x52800000):
                    continue
                for slot in items:
                    if slot[2:] != (9, 0, 0x52800000):
                        continue
                    if base_offset >= min(total[0], slot[0]):
                        continue
                    if max(base_offset, total[0], slot[0]) - min(base_offset, total[0], slot[0]) > 0x24:
                        continue
                    if total[1] == slot[1] * 4:
                        candidates.append((base, total[1], slot[1]))
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RuntimeError(f"input layout: {candidates}")
    return candidates[0]


def send_info(data, bss_start, bss_end):
    setters = []
    for offset in range(0, len(data) - 0x18, 4):
        words = [u32(data, offset + index * 4) for index in range(6)]
        if words[0] & 0x9F00001F != 0x90000008:
            continue
        if words[1] & 0x9F00001F != 0x90000009:
            continue
        if words[2] & 0xFFC003FF != 0xF9000100:
            continue
        if words[3] != 0x2A1F03E0:
            continue
        if words[4] & 0xFFC003FF != 0xF9000121 or words[5] != 0xD65F03C0:
            continue
        first_page, _ = adrp(words[0], LK_BASE + offset)
        second_page, _ = adrp(words[1], LK_BASE + offset + 4)
        first = first_page + ((words[2] >> 10) & 0xFFF) * 8
        second = second_page + ((words[4] >> 10) & 0xFFF) * 8
        if second == first + 8:
            setters.append((LK_BASE + offset, first))
    if len(setters) != 1:
        raise RuntimeError(f"Odin setter: {setters}")
    setter, callback = setters[0]

    callers = []
    for off in range(16, len(data), 4):
        insn = u32(data, off)
        if insn & 0xFC000000 != 0x14000000:
            continue
        imm = insn & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        if LK_BASE + off + (imm << 2) != setter:
            continue
        words = [u32(data, off - 16 + index * 4) for index in range(4)]
        if words[0] & 0x9F00001F != 0x90000000:
            continue
        if words[1] & 0x9F00001F != 0x90000001:
            continue
        page0, reg0 = adrp(words[0], LK_BASE + off - 16)
        page1, reg1 = adrp(words[1], LK_BASE + off - 12)
        val0, dst0, src0 = add_imm(words[2])
        val1, dst1, src1 = add_imm(words[3])
        if (reg0, dst0, src0) != (0, 0, 0):
            continue
        if (reg1, dst1, src1) != (1, 1, 1):
            continue
        callers.append((page0 + val0, page1 + val1))
    if len(callers) != 1:
        raise RuntimeError(f"Odin registration: {callers}")
    default_send, _ = callers[0]

    uses = []
    for offset in range(0, len(data) - 0x10, 4):
        words = [u32(data, offset + index * 4) for index in range(4)]
        if words[0] & 0x9F000000 != 0x90000000:
            continue
        page, register = adrp(words[0], LK_BASE + offset)
        if words[1] & 0xFFC00000 != 0xF9400000:
            continue
        if (words[1] >> 5) & 31 != register:
            continue
        address = page + ((words[1] >> 10) & 0xFFF) * 8
        target = words[1] & 31
        if (address == callback and words[2] == 0x52800101 and
                words[3] == (0xD63F0000 | (target << 5))):
            uses.append(offset)
    if not uses:
        raise RuntimeError("Odin callback XREF not found")

    counts = collections.Counter()
    for use in uses:
        found = set()
        for offset in range(max(0, use - 0x100), use, 4):
            instruction = u32(data, offset)
            if instruction & 0x9F000000 != 0x90000000:
                continue
            page, register = adrp(instruction, LK_BASE + offset)
            for second in range(offset + 4, min(use, offset + 0x24), 4):
                load = u32(data, second)
                if (load & 0xFFC00000 == 0xF9400000 and
                        (load >> 5) & 31 == register and load & 31 == 0):
                    address = page + ((load >> 10) & 0xFFF) * 8
                    if bss_start <= address < bss_end:
                        found.add(address)
        counts.update(found)
    reply = [addr for addr, count in counts.items() if count == len(uses)]
    if len(reply) != 1 or not 0 < callback - reply[0] <= PAGE_SIZE:
        raise RuntimeError(f"Odin reply: {reply}")
    return reply[0], callback, default_send


def comp_output(data):
    candidates = []
    for offset in range(0, len(data) - 0x28, 4):
        words = [u32(data, offset + index * 4) for index in range(10)]
        if words[0] & 0x9F00001F != 0x90000008:
            continue
        if words[1] & 0xFFC003FF != 0xB9400108:
            continue
        if words[2:6] != [0xF85F83B4, 0xAA1A03E1, 0xAA1803E2, 0x7100011F]:
            continue
        base = mov_wide(words[6])
        if not base or base[1:] != (8, 0, 0x52800000):
            continue
        if words[7:9] != [0x9A950108, 0x8B140100]:
            continue
        if words[9] & 0xFC000000 != 0x94000000:
            continue
        candidates.append((base[0], offset))
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RuntimeError(f"compressed output: {candidates}")
    base, site = candidates[0]
    values = collections.Counter()
    for offset in range(max(0, site - 0x400), min(len(data), site + 0x200), 4):
        item = mov_wide(u32(data, offset))
        if (item and item[3] == 0x52800000 and item[0] >= 0x10000 and
                item[0] <= 0x400000 and item[0] & (item[0] - 1) == 0):
            values[item[0]] += 1
    repeated = [value for value, count in values.items() if count >= 2]
    if len(repeated) != 1:
        raise RuntimeError(f"compressed block: {repeated}")
    return base, repeated[0]


def screen_fns(data):
    prologue = struct.pack(
        "<6I",
        0xA9BC7BFD, 0xA9015FFC, 0xA90257F6,
        0xA9034FF4, 0x910003FD, 0xD11383FF,
    )
    screen_printf = unique(data, prologue, "screen printf")
    printf_addr = LK_BASE + screen_printf
    def call_target(off):
        insn = u32(data, off)
        if insn & 0xFC000000 != 0x94000000:
            return None
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return LK_BASE + off + imm * 4

    calls = []
    for off in range(0, len(data) - 8, 4):
        if call_target(off) == printf_addr:
            calls.append(off)
    cursors = collections.Counter()
    for call in calls:
        cursors.update({target for off in range(max(0, call - 0x40), call, 4)
                        if (target := call_target(off)) is not None})
    cursor, count = cursors.most_common(1)[0]
    start = cursor - LK_BASE
    words = tuple(u32(data, start + index * 4) for index in range(3))
    if (count * 2 < len(calls) or list(cursors.values()).count(count) != 1 or
            words[0] & 0x9F00001F != 0x90000008 or
            words[1] & 0xFFC003FF != 0xB9400100 or words[2] != 0xD65F03C0):
        raise RuntimeError(f"screen cursor: {cursors}")

    updates = collections.Counter(
        target for call in calls if (target := call_target(call + 4)) is not None
    )
    if not updates:
        raise RuntimeError("display update XREF not found")
    update, count = updates.most_common(1)[0]
    if count < 10 or list(updates.values()).count(count) != 1:
        raise RuntimeError(f"display update: {updates}")
    start = update - LK_BASE
    if tuple(u32(data, start + index * 4) for index in range(3)) != (
            0xA9BE7BFD, 0xF9000BF3, 0x910003FD):
        raise RuntimeError("display update prologue")
    return cursor, printf_addr, update


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=Path)
    a = ap.parse_args()
    path = a.image.resolve()
    data = load_lk(path)
    if b"s5e8825\0" not in data:
        raise RuntimeError("image is not an S5E8825 LK build")

    global LK_BASE
    LK_BASE, _, bss_lo, bss_hi = image_map(data)
    in_base, in_total, in_slot = input_map(data)
    par_base, par_total, par_slot = parallel(data)
    out_base, block = comp_output(data)
    reply, callback, send = send_info(data, bss_lo, bss_hi)

    maps = []
    for off in range(0, len(data) - 0x28, 8):
        ent = struct.unpack_from("<5Q", data, off)
        if ent[1] == in_base and ent[2] >= in_base + in_total and ent[3] == in_base:
            maps.append(ent)
    if len(maps) != 1 or maps[0][4] & ((1 << 53) | (1 << 54)):
        raise RuntimeError("payload staging area is not executable")

    slots = in_total // in_slot
    if slots < 2 or in_total != slots * in_slot:
        raise RuntimeError("unexpected V3 slot count")
    par_slots = par_total // par_slot
    if par_slots < 2 or par_total < par_slots * par_slot:
        raise RuntimeError("unexpected parallel V3 slot count")
    if slots < 4:
        raise RuntimeError("loader needs four V3 input slots")
    if slots != par_slots:
        raise RuntimeError("input and parallel slot counts differ")
    code_slot = slots - 1
    pack_slot = code_slot - 1
    code_base = in_base + code_slot * in_slot
    code = code_base + CODE_OFFSET
    reserve = block
    pack_base = in_base + pack_slot * in_slot
    pack = pack_base + reserve
    write = reply
    cb_off = callback - write
    ctl_len = cb_off + 8
    walk = write - out_base
    if not 0 < walk < 1 << 32:
        raise RuntimeError("USB callback is outside the accumulator walk")
    if not bss_lo < callback < bss_hi:
        raise RuntimeError("USB callback is outside LK BSS")
    code_end = in_base + (code_slot + 1) * in_slot
    reply_buf = code_end - PAGE_SIZE
    work = pack_base + in_slot - 4 * PAGE_SIZE
    pit = work - 4 * PAGE_SIZE
    pack_cap = min(pit - pack, par_slot - reserve)
    if (reply_buf + 8 > code_end or pack_cap <= 0 or
            code + CODE_CAPACITY > code_base + PAGE_SIZE or
            reserve >= par_slot or pit <= pack):
        raise RuntimeError("invalid loader memory layout")
    bread = named_fn(data, b"blk_bread", 168)
    bwrite = named_fn(data, b"blk_bwrite", 176)
    shift = io_shift(data, bread)
    sha256 = sha256_fn(data)
    cursor, screen, update = screen_fns(data)

    (HERE / "offsets.py").write_text(
        f"BLOCK = {block:#x}\n"
        f"CB_OFF = {cb_off:#x}\n"
        f"OUT_BASE = {out_base:#x}\n"
        f"CTL_LEN = {ctl_len:#x}\n"
        f"WALK_LEN = {walk:#x}\n"
        f"CODE_OFF = {CODE_OFFSET:#x}\n"
        f"CODE_ADDR = {code:#x}\n"
        f"CODE_MAX = {CODE_CAPACITY:#x}\n"
        f"PACK_SLOT = {pack_slot}\n"
        f"RESERVE = {reserve:#x}\n"
        f"PACK_ADDR = {pack:#x}\n"
        f"PACK_MAX = {pack_cap:#x}\n"
        f"IN_BASE = {in_base:#x}\n"
        f"IN_SIZE = {in_total:#x}\n"
        f"IN_SLOT = {in_slot:#x}\n"
        f"RAW_ADDR = {in_base:#x}\n"
        f"READ_ADDR = {in_base + in_slot:#x}\n"
        f"PIT_ADDR = {pit:#x}\n"
        f"PIT_MAX = {4 * PAGE_SIZE:#x}\n"
        f"LZMA_ADDR = {work:#x}\n"
        f"LZMA_MAX = {4 * PAGE_SIZE:#x}\n"
        f"REPLY_ADDR = {reply_buf:#x}\n"
        f"CODE_SLOT = {code_slot}\n"
        f"PAR_BASE = {par_base:#x}\n"
        f"PAR_SIZE = {par_total:#x}\n"
        f"PAR_SLOT = {par_slot:#x}\n"
        f"WRITE_ADDR = {write:#x}\n"
        f"BLK_SHIFT = {shift}\n",
        encoding="utf-8",
    )
    loader_profile = (
        f"#define SEND_CALLBACK {callback:#x}ULL\n"
        f"#define SEND_CALLBACK_DEFAULT {send:#x}ULL\n"
        f"#define BLK_BREAD {bread:#x}ULL\n"
        f"#define BLK_BWRITE {bwrite:#x}ULL\n"
        f"#define BLK_SHIFT {shift}U\n"
        f"#define SHA256 {sha256:#x}ULL\n"
        f"#define SCREEN_CURSOR {cursor:#x}ULL\n"
        f"#define SCREEN_PRINTF {screen:#x}ULL\n"
        f"#define DISPLAY_UPDATE {update:#x}ULL\n"
        f"#define DECOMPRESS_ADDRESS {in_base:#x}ULL\n"
        f"#define DECOMPRESS_CAPACITY {in_slot:#x}U\n"
        f"#define READBACK_ADDRESS {in_base + in_slot:#x}ULL\n"
        f"#define READBACK_CAPACITY {in_slot:#x}U\n"
        f"#define PIT_ADDRESS {pit:#x}ULL\n"
        f"#define PIT_CAPACITY {4 * PAGE_SIZE:#x}U\n"
        f"#define LZMA_WORKSPACE_ADDRESS {work:#x}ULL\n"
        f"#define LZMA_WORKSPACE_CAPACITY {PAGE_SIZE * 4:#x}U\n"
        f"#define CODE_ADDRESS {code:#x}ULL\n"
        f"#define CODE_CAPACITY {CODE_CAPACITY:#x}U\n"
        f"#define BUNDLE_ADDRESS {pack:#x}ULL\n"
        f"#define BUNDLE_CAPACITY {pack_cap:#x}U\n"
        f"#define PAYLOAD_CAPACITY {CODE_CAPACITY:#x}U\n"
    )
    (HERE / "loader_profile.h").write_text(
        loader_profile,
        encoding="utf-8",
    )
    (HERE / "link.ld").write_text(
        "ENTRY(_start)\n"
        "SECTIONS\n"
        "{\n"
        f"    . = {code:#x};\n"
        "    __code_start = .;\n"
        "    .code : { KEEP(*(.text.entry)) KEEP(*(.text.keep)) *(.text*) *(.rodata*) *(.data*) }\n"
        "    __code_end = .;\n"
        f"    ASSERT(__code_end - __code_start <= {CODE_CAPACITY:#x}, \"code exceeds {CODE_CAPACITY} bytes\")\n"
        "    .bss (NOLOAD) : { *(.bss*) *(COMMON) }\n"
        "    ASSERT(SIZEOF(.bss) == 0, \"payload must not use BSS\")\n"
        "    /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }\n"
        "}\n",
        encoding="utf-8",
    )
    print(
        f"{path} {hashlib.sha256(data).hexdigest()} base={LK_BASE:#x} "
        f"in={in_base:#x} pack={pack:#x} code={code:#x} out={out_base:#x} "
        f"write={write:#x} cb={callback:#x} walk={walk:#x}"
    )


if __name__ == "__main__":
    main()
