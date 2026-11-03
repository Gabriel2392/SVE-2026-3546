import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


HEADER = 0x100
FOOTER = 0x40


def _u32(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from(">I", buf, off)[0]


def _u64(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from(">Q", buf, off)[0]


def _p64(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into(">Q", buf, off, val)


def _text(buf: bytes | bytearray) -> str:
    return bytes(buf).split(b"\0", 1)[0].decode("ascii")


@dataclass(frozen=True)
class Head:
    off: int
    auth: int
    aux: int
    alg: int
    hash_off: int
    hash_len: int
    sig_off: int
    sig_len: int
    key_off: int
    key_len: int
    desc_off: int
    desc_len: int

    @property
    def auth_at(self) -> int:
        return self.off + HEADER

    @property
    def aux_at(self) -> int:
        return self.auth_at + self.auth

    @property
    def size(self) -> int:
        return HEADER + self.auth + self.aux


@dataclass(frozen=True)
class Desc:
    tag: int
    start: int
    end: int
    name: str | None


@dataclass(frozen=True)
class Foot:
    original: int
    vbmeta: int
    size: int


def footer(buf: bytes | bytearray) -> Foot | None:
    if len(buf) < FOOTER or buf[-FOOTER:-FOOTER + 4] != b"AVBf":
        return None
    off = len(buf) - FOOTER
    val = Foot(_u64(buf, off + 12), _u64(buf, off + 20), _u64(buf, off + 28))
    if not 0 < val.original <= val.vbmeta or val.vbmeta + val.size > off:
        raise ValueError("invalid AVB footer")
    return val


def head(buf: bytes | bytearray, off: int = 0) -> Head:
    if off < 0 or off + HEADER > len(buf) or buf[off:off + 4] != b"AVB0":
        raise ValueError("invalid AVB header")
    val = Head(
        off,
        _u64(buf, off + 12),
        _u64(buf, off + 20),
        _u32(buf, off + 28),
        _u64(buf, off + 32),
        _u64(buf, off + 40),
        _u64(buf, off + 48),
        _u64(buf, off + 56),
        _u64(buf, off + 64),
        _u64(buf, off + 72),
        _u64(buf, off + 96),
        _u64(buf, off + 104),
    )
    if val.alg != 2 or (val.auth, val.hash_len, val.sig_len, val.key_len) != (576, 32, 512, 1032):
        raise ValueError("unsupported AVB signing mode")
    if val.off + val.size > len(buf):
        raise ValueError("truncated AVB image")
    if val.hash_off + val.hash_len > val.auth or val.sig_off + val.sig_len > val.auth:
        raise ValueError("invalid AVB authentication layout")
    if val.key_off + val.key_len > val.aux or val.desc_off + val.desc_len > val.aux:
        raise ValueError("invalid AVB auxiliary layout")
    return val


def _name(buf: bytes | bytearray, tag: int, off: int, end: int) -> str | None:
    if tag == 1:
        fixed, pos = 180, 104
    elif tag == 2:
        fixed, pos = 132, 56
    elif tag == 4:
        fixed, pos = 92, 20
    else:
        return None
    size = _u32(buf, off + pos)
    if off + fixed + size > end:
        raise ValueError("truncated AVB descriptor name")
    return bytes(buf[off + fixed:off + fixed + size]).decode("ascii")


def descs(buf: bytes | bytearray, hdr: Head) -> list[Desc]:
    pos = hdr.aux_at + hdr.desc_off
    end = pos + hdr.desc_len
    out = []
    while pos < end:
        if pos + 16 > end:
            raise ValueError("truncated AVB descriptor")
        tag = _u64(buf, pos)
        stop = pos + 16 + _u64(buf, pos + 8)
        if stop > end:
            raise ValueError("AVB descriptor exceeds its block")
        out.append(Desc(tag, pos, stop, _name(buf, tag, pos, stop)))
        pos = stop
    return out


def _hash(buf: bytes | bytearray, desc: Desc) -> tuple[str, bytes, bytes, int]:
    if desc.tag != 2 or desc.start + 132 > desc.end:
        raise ValueError("descriptor is not an AVB hash descriptor")
    off = desc.start
    name_len = _u32(buf, off + 56)
    salt_len = _u32(buf, off + 60)
    digest_len = _u32(buf, off + 64)
    pos = off + 132
    if pos + name_len + salt_len + digest_len > desc.end:
        raise ValueError("truncated AVB hash descriptor")
    name = bytes(buf[pos:pos + name_len]).decode("ascii")
    pos += name_len
    salt = bytes(buf[pos:pos + salt_len])
    pos += salt_len
    digest = bytes(buf[pos:pos + digest_len])
    return name, salt, digest, _u64(buf, off + 16)


def _set_hash(buf: bytearray, desc: Desc, data: bytes, size: int) -> bytes:
    name, salt, old, _ = _hash(buf, desc)
    alg = _text(buf[desc.start + 24:desc.start + 56])
    if alg != "sha256" or len(old) != 32:
        raise ValueError(f"unsupported hash descriptor for {name}")
    digest = hashlib.sha256(salt + data[:size]).digest()
    _p64(buf, desc.start + 16, size)
    name_len = _u32(buf, desc.start + 56)
    salt_len = _u32(buf, desc.start + 60)
    pos = desc.start + 132 + name_len + salt_len
    buf[pos:pos + 32] = digest
    return bytes(buf[desc.start:desc.end])


def _chain(buf: bytearray, desc: Desc, pub: bytes) -> None:
    if desc.tag != 4:
        return
    name_len = _u32(buf, desc.start + 20)
    key_len = _u32(buf, desc.start + 24)
    if key_len != len(pub):
        raise ValueError(f"AVB chain key size mismatch for {desc.name}")
    pos = desc.start + 92 + name_len
    if pos + key_len > desc.end:
        raise ValueError("truncated AVB chain descriptor")
    buf[pos:pos + key_len] = pub


def _key(buf: bytes | bytearray, hdr: Head) -> bytes:
    pos = hdr.aux_at + hdr.key_off
    return bytes(buf[pos:pos + hdr.key_len])


def public(buf: bytes | bytearray, hdr: Head | None = None) -> bytes:
    return _key(buf, hdr or head(buf))


def _sign(buf: bytearray, hdr: Head, key: rsa.RSAPrivateKey, pub: bytes) -> None:
    pos = hdr.aux_at + hdr.key_off
    buf[pos:pos + hdr.key_len] = pub
    block = bytes(buf[hdr.off:hdr.off + HEADER]) + bytes(buf[hdr.aux_at:hdr.aux_at + hdr.aux])
    digest = hashlib.sha256(block).digest()
    sig = key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    if len(sig) != hdr.sig_len:
        raise ValueError("invalid AVB RSA signature size")
    buf[hdr.auth_at + hdr.hash_off:hdr.auth_at + hdr.hash_off + hdr.hash_len] = digest
    buf[hdr.auth_at + hdr.sig_off:hdr.auth_at + hdr.sig_off + hdr.sig_len] = sig


def _pub(blob: bytes) -> rsa.RSAPublicKey:
    if len(blob) < 8:
        raise ValueError("invalid AVB public key")
    bits = int.from_bytes(blob[:4], "big")
    size = bits // 8
    if bits != 4096 or len(blob) != 8 + size * 2:
        raise ValueError("unsupported AVB public key")
    n = int.from_bytes(blob[8:8 + size], "big")
    return rsa.RSAPublicNumbers(65537, n).public_key()


def verify_meta(buf: bytes | bytearray, hdr: Head, pub: bytes | None = None) -> None:
    stored = _key(buf, hdr)
    if pub is not None and stored != pub:
        raise ValueError("AVB public key mismatch")
    block = bytes(buf[hdr.off:hdr.off + HEADER]) + bytes(buf[hdr.aux_at:hdr.aux_at + hdr.aux])
    digest = hashlib.sha256(block).digest()
    got = bytes(buf[hdr.auth_at + hdr.hash_off:hdr.auth_at + hdr.hash_off + hdr.hash_len])
    if got != digest:
        raise ValueError("invalid AVB digest")
    sig = bytes(buf[hdr.auth_at + hdr.sig_off:hdr.auth_at + hdr.sig_off + hdr.sig_len])
    try:
        _pub(stored).verify(sig, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    except Exception as exc:
        raise ValueError("invalid AVB signature") from exc


def wrap(buf: bytearray, key: rsa.RSAPrivateKey, pub: bytes,
         name: str) -> bytes:
    foot = footer(buf)
    if foot is None:
        raise ValueError(f"{name} has no AVB footer")
    hdr = head(buf, foot.vbmeta)
    if hdr.size != foot.size:
        raise ValueError(f"{name} AVB size mismatch")
    items = [item for item in descs(buf, hdr) if item.tag == 2]
    if len(items) != 1 or items[0].name != name:
        raise ValueError(f"unexpected AVB descriptors for {name}")
    raw = _set_hash(buf, items[0], bytes(buf), foot.original)
    for item in descs(buf, hdr):
        _chain(buf, item, pub)
    _sign(buf, hdr, key, pub)
    verify_wrap(buf, pub, name)
    return raw


def update_top(buf: bytearray, key: rsa.RSAPrivateKey, pub: bytes,
               updates: dict[str, bytes]) -> None:
    hdr = head(buf)
    items = descs(buf, hdr)
    seen = set()
    for item in items:
        _chain(buf, item, pub)
        if item.tag == 2 and item.name in updates:
            raw = updates[item.name]
            if len(raw) != item.end - item.start:
                raise ValueError(f"AVB descriptor size changed for {item.name}")
            buf[item.start:item.end] = raw
            seen.add(item.name)
    missing = set(updates) - seen
    if missing:
        raise ValueError(f"top-level vbmeta is missing descriptors: {sorted(missing)}")
    _sign(buf, hdr, key, pub)
    verify_top(buf, pub, updates)


def verify_wrap(buf: bytes | bytearray, pub: bytes | None, name: str) -> bytes:
    foot = footer(buf)
    if foot is None:
        raise ValueError(f"{name} has no AVB footer")
    hdr = head(buf, foot.vbmeta)
    verify_meta(buf, hdr, pub)
    items = [item for item in descs(buf, hdr) if item.tag == 2]
    if len(items) != 1 or items[0].name != name:
        raise ValueError(f"unexpected AVB descriptors for {name}")
    _, salt, digest, size = _hash(buf, items[0])
    if size != foot.original or hashlib.sha256(salt + bytes(buf[:size])).digest() != digest:
        raise ValueError(f"AVB hash mismatch for {name}")
    return bytes(buf[items[0].start:items[0].end])


def verify_top(buf: bytes | bytearray, pub: bytes,
               updates: dict[str, bytes]) -> None:
    hdr = head(buf)
    verify_meta(buf, hdr, pub)
    found = set()
    for item in descs(buf, hdr):
        if item.tag == 4:
            name_len = _u32(buf, item.start + 20)
            key_len = _u32(buf, item.start + 24)
            pos = item.start + 92 + name_len
            if bytes(buf[pos:pos + key_len]) != pub:
                raise ValueError(f"AVB chain key mismatch for {item.name}")
        if item.tag == 2 and item.name in updates:
            if bytes(buf[item.start:item.end]) != updates[item.name]:
                raise ValueError(f"top-level hash mismatch for {item.name}")
            found.add(item.name)
    if found != set(updates):
        raise ValueError("top-level AVB descriptor set mismatch")
