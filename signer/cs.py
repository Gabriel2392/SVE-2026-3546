import hashlib
import hmac
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


ST1_FOOTER = 2360
ST2_FOOTER = 0x210
ST2_SKIP = 0x200
INFO_SIZE = 0x100
INFO_MARKER = b"SignerVer03"


def _u32(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _p32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val)


def boundary(buf: bytes | bytearray) -> int:
    if len(buf) >= 0x40 and buf[-0x40:-0x3C] == b"AVBf":
        val = struct.unpack_from(">Q", buf, len(buf) - 0x34)[0]
        if not 0 < val <= len(buf):
            raise ValueError("invalid AVB boundary")
        return val
    return len(buf)


def signer_info(buf: bytes | bytearray) -> dict[str, str]:
    off = boundary(buf) - ST2_FOOTER - INFO_SIZE
    if off < 0 or bytes(buf[off:off + len(INFO_MARKER)]) != INFO_MARKER:
        raise ValueError("CodeSigner metadata is missing")

    def text(start: int, size: int) -> str:
        raw = bytes(buf[off + start:off + start + size]).split(b"\0", 1)[0]
        return raw.decode("ascii")

    return {
        "firmware": text(0x20, 0x20),
        "product": text(0x50, 0x20),
        "keyset": text(0x70, 0x20),
        "image": text(0x9C, 0x64),
    }


def pub_blob(key: ec.EllipticCurvePrivateKey) -> bytes:
    pub = key.public_key().public_numbers()
    out = bytearray(524)
    out[20:68] = pub.x.to_bytes(48, "big")
    out[88:136] = pub.y.to_bytes(48, "big")
    return bytes(out)


def pub_key(blob: bytes) -> ec.EllipticCurvePublicKey:
    if len(blob) < 136 or any(blob[:20]) or any(blob[68:88]):
        raise ValueError("invalid P-384 public blob")
    val = ec.EllipticCurvePublicNumbers(
        int.from_bytes(blob[20:68], "big"),
        int.from_bytes(blob[88:136], "big"),
        ec.SECP384R1(),
    )
    return val.public_key()


def _sig(key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA512())))
    r, s = decode_dss_signature(der)
    return bytes(20) + r.to_bytes(48, "big") + bytes(20) + s.to_bytes(48, "big")


def _verify(key: ec.EllipticCurvePublicKey, digest: bytes, sig: bytes) -> bool:
    if len(sig) != 136 or any(sig[:20]) or any(sig[68:88]):
        return False
    der = encode_dss_signature(
        int.from_bytes(sig[20:68], "big"),
        int.from_bytes(sig[88:136], "big"),
    )
    try:
        key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA512())))
        return True
    except Exception:
        return False


def _ec(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError(f"{path} is not a P-384 private key")
    return key


def avb_key_size(buf: bytes) -> int | None:
    if len(buf) < 8:
        return None
    bits = int.from_bytes(buf[:4], "big")
    if bits < 1024 or bits % 8:
        return None
    size = 8 + bits // 4
    if len(buf) < size:
        return None
    width = bits // 8
    n = int.from_bytes(buf[8:8 + width], "big")
    if n.bit_length() != bits or not n & 1:
        return None
    low = n & 0xffffffff
    if int.from_bytes(buf[4:8], "big") != (-pow(low, -1, 1 << 32)) & 0xffffffff:
        return None
    expected_rr = pow(2, bits * 2, n).to_bytes(width, "big")
    if buf[8 + width:8 + width * 2] != expected_rr:
        return None
    return size


@dataclass(frozen=True)
class Keys:
    st1: ec.EllipticCurvePrivateKey
    tee: ec.EllipticCurvePrivateKey
    ree: ec.EllipticCurvePrivateKey
    hmac_key: bytes
    avb: rsa.RSAPrivateKey
    avb_pub: bytes

    @classmethod
    def load(cls, root: Path) -> "Keys":
        key4 = root / "4"
        hm = (root / "hmac.bin").read_bytes()
        if len(hm) != 32:
            raise ValueError("hmac.bin must be 32 bytes")
        avb = serialization.load_pem_private_key((root / "avb.pem").read_bytes(), None)
        if not isinstance(avb, rsa.RSAPrivateKey) or avb.key_size != 4096:
            raise ValueError("avb.pem is not an RSA-4096 private key")
        avb_pub = (root / "avb.pubkey").read_bytes()
        size = avb_key_size(avb_pub)
        if size != len(avb_pub):
            raise ValueError("avb.pubkey has an invalid AVB RSA layout")
        bits = int.from_bytes(avb_pub[:4], "big")
        n = int.from_bytes(avb_pub[8:8 + bits // 8], "big")
        if n != avb.public_key().public_numbers().n:
            raise ValueError("avb.pem and avb.pubkey do not match")
        return cls(
            _ec(key4 / "st1.pem"),
            _ec(key4 / "st2t.pem"),
            _ec(key4 / "st2r.pem"),
            hm,
            avb,
            avb_pub,
        )

    def key(self, mode: str) -> ec.EllipticCurvePrivateKey:
        if mode == "tee":
            return self.tee
        if mode == "ree":
            return self.ree
        raise ValueError(f"invalid ST2 key mode: {mode}")


def sign_st1(buf: bytearray, keys: Keys, rb: int | None = None,
             image_type: int = 4) -> None:
    size = _u32(buf, 0) * 512
    if size != len(buf) or size < ST1_FOOTER:
        raise ValueError("invalid ST1 image size")
    foot = size - ST1_FOOTER
    if _u32(buf, foot + 8) != 5 or _u32(buf, foot + 28) != image_type:
        raise ValueError("ST1 is not CodeSigner v5")
    if rb is not None:
        _p32(buf, foot + 24, rb)
    tee = pub_blob(keys.tee)
    ree = pub_blob(keys.ree)
    st1 = pub_blob(keys.st1)
    buf[foot + 100:foot + 624] = tee
    buf[foot + 624:foot + 1148] = ree
    buf[foot + 1288:foot + 1812] = st1
    buf[foot + 1812:foot + 1844] = hmac.new(keys.hmac_key, st1[:136], hashlib.sha512).digest()[:32]
    _p32(buf, foot + 1844, 136)
    buf[4:8] = bytes(4)
    at = foot + 1848
    buf[at:at + 136] = _sig(keys.st1, hashlib.sha512(buf[:at]).digest())
    buf[4:8] = hashlib.sha512(buf[16:]).digest()[:4]
    verify_st1(buf, keys, image_type)


def verify_st1(buf: bytes | bytearray, keys: Keys | None = None,
               image_type: int = 4) -> dict:
    size = _u32(buf, 0) * 512
    if size != len(buf) or size < ST1_FOOTER:
        raise ValueError("invalid ST1 image size")
    foot = size - ST1_FOOTER
    if _u32(buf, foot + 8) != 5 or _u32(buf, foot + 28) != image_type:
        raise ValueError("invalid ST1 CodeSigner mode")
    tee = bytes(buf[foot + 100:foot + 624])
    ree = bytes(buf[foot + 624:foot + 1148])
    st1 = bytes(buf[foot + 1288:foot + 1812])
    chk = bytearray(buf)
    chk[4:8] = bytes(4)
    at = foot + 1848
    if not _verify(pub_key(st1), hashlib.sha512(chk[:at]).digest(), bytes(buf[at:at + 136])):
        raise ValueError("invalid ST1 signature")
    if keys is not None:
        if tee != pub_blob(keys.tee) or ree != pub_blob(keys.ree) or st1 != pub_blob(keys.st1):
            raise ValueError("ST1 public keys do not match the selected keys")
        want = hmac.new(keys.hmac_key, st1[:136], hashlib.sha512).digest()[:32]
        if bytes(buf[foot + 1812:foot + 1844]) != want:
            raise ValueError("invalid ST1 HMAC")
    return {"version": 5, "type": 4, "rollback": _u32(buf, foot + 24)}


def sign_st2(buf: bytearray, keys: Keys, mode: str, header: bool = False,
             rb: int | None = None, image_type: int = 4) -> None:
    end = boundary(buf)
    if end < ST2_FOOTER:
        raise ValueError("ST2 image is too small")
    foot = end - ST2_FOOTER
    key = keys.key(mode)
    kind = 0 if mode == "tee" else 1
    if _u32(buf, foot + 4) != image_type or _u32(buf, foot + 8) not in (0, 1):
        raise ValueError(f"invalid ST2 footer at {foot:#x}")
    if rb is not None:
        _p32(buf, foot, rb)
    _p32(buf, foot + 4, image_type)
    _p32(buf, foot + 8, kind)
    _p32(buf, foot + 12, zlib.crc32(pub_blob(key)))
    if header:
        buf[4:8] = bytes(4)
    at = end - ST2_SKIP
    buf[at:at + 136] = _sig(key, hashlib.sha512(buf[:at]).digest())
    if header:
        buf[4:8] = hashlib.sha512(buf[16:]).digest()[:4]
    verify_st2(buf, key.public_key(), mode, header, image_type)


def verify_st2(buf: bytes | bytearray, key: ec.EllipticCurvePublicKey,
               mode: str, header: bool = False, image_type: int = 4) -> dict:
    end = boundary(buf)
    foot = end - ST2_FOOTER
    kind = 0 if mode == "tee" else 1
    if (end < ST2_FOOTER or _u32(buf, foot + 4) != image_type or
            _u32(buf, foot + 8) != kind):
        raise ValueError("ST2 mode mismatch")
    at = end - ST2_SKIP
    if header:
        h = hashlib.sha512()
        h.update(buf[:4])
        h.update(bytes(4))
        h.update(buf[8:at])
        digest = h.digest()
    else:
        digest = hashlib.sha512(buf[:at]).digest()
    if not _verify(key, digest, bytes(buf[at:at + 136])):
        raise ValueError("invalid ST2 signature")
    return {
        "version": 5,
        "type": 4,
        "key": mode,
        "rollback": _u32(buf, foot),
        "key_index": f"{_u32(buf, foot + 12):08x}",
    }


def stock_keys(fld: bytes, image_type: int = 4) -> tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePublicKey]:
    size = _u32(fld, 0) * 512
    foot = size - ST1_FOOTER
    if (size > len(fld) or _u32(fld, foot + 8) != 5 or
            _u32(fld, foot + 28) != image_type):
        raise ValueError("invalid stock FLD")
    return pub_key(fld[foot + 100:foot + 624]), pub_key(fld[foot + 624:foot + 1148])


def _key_table(buf: bytes | bytearray) -> tuple[int, int, int, int, int, int, int, int]:
    if not buf.startswith(b"SLSI") or len(buf) < 48:
        raise ValueError("invalid SLSI keystorage")
    version = _u32(buf, 4)
    if version not in (0x20, 0x30, 0x40, 0x50):
        raise ValueError("invalid keystorage version")
    header = _u32(buf, 8)
    count = _u32(buf, 12)
    body = _u32(buf, 0x20)
    record = 2592 if version >= 0x50 else 1056
    whitelist = 24 if version >= 0x50 else 12
    meta = 48 + (whitelist * 16 if version >= 0x30 else 0)
    name_len = 16 if version >= 0x40 else 8
    meta_len = name_len + 8
    slots = (header - meta) // meta_len if header >= meta else 0
    if (not count or header < meta or (header - meta) % meta_len
            or count > slots or body != count * record
            or header + body > len(buf)):
        raise ValueError("invalid keystorage table")
    return version, header, count, record, meta, name_len, meta_len, slots


def replace_avb_keys(buf: bytearray, pub: bytes) -> list[int]:
    _, header, count, record, meta, name_len, meta_len, _ = _key_table(buf)
    found = []
    names = set()
    for slot in range(count):
        item = meta + slot * meta_len
        raw_name = bytes(buf[item:item + name_len])
        name = raw_name.split(b"\0", 1)[0]
        if not name or any(raw_name[len(name):]) or name in names:
            raise ValueError("invalid keystorage key name")
        names.add(name)
        index = _u32(buf, item + name_len)
        kind = _u32(buf, item + name_len + 4)
        at = header + slot * record
        raw = bytes(buf[at:at + record])
        if kind == 4:
            if len(raw) < 524 or any(raw[524:]) or zlib.crc32(raw[:524]) != index:
                raise ValueError("invalid keystorage P-384 key")
            pub_key(raw[:524])
            continue
        if kind != 0xff:
            raise ValueError("unsupported keystorage key type")
        size = avb_key_size(raw)
        if size is None or size != len(pub) or any(raw[size:]):
            raise ValueError("keystorage AVB key size mismatch")
        buf[at:at + size] = pub
        _p32(buf, item + name_len, zlib.crc32(pub))
        found.append(at)
    if not found:
        raise ValueError("keystorage has no AVB keys")
    return found


def provision_fw_key(buf: bytearray, pub: bytes) -> int:
    version, header, count, record, meta, name_len, meta_len, slots = _key_table(buf)
    if version < 0x40 or len(pub) != 524:
        raise ValueError("unsupported keystorage firmware key")
    pub_key(pub)
    index = zlib.crc32(pub)
    if not index:
        raise ValueError("invalid keystorage firmware key index")
    target = None
    indexes = set()
    names = set()
    for slot in range(count):
        item = meta + slot * meta_len
        raw_name = bytes(buf[item:item + name_len])
        name = raw_name.split(b"\0", 1)[0]
        current = _u32(buf, item + name_len)
        if not name or any(raw_name[len(name):]) or name in names or current in indexes:
            raise ValueError("duplicate keystorage key")
        names.add(name)
        indexes.add(current)
        if name == b"fw_key":
            if target is not None or _u32(buf, item + name_len + 4) != 4:
                raise ValueError("invalid keystorage firmware key")
            target = slot
    if target is None:
        if index in indexes:
            raise ValueError("duplicate keystorage firmware key")
        if count >= slots:
            raise ValueError("keystorage metadata is full")
        target = count
        item = meta + target * meta_len
        raw_name = bytes(buf[item:item + name_len])
        empty = (bytes(name_len), b"none" + bytes(name_len - 4))
        if raw_name not in empty or any(buf[item + name_len:item + meta_len]):
            raise ValueError("keystorage metadata slot is not empty")
        at = header + target * record
        if at + record > boundary(buf) - ST2_FOOTER or any(buf[at:at + record]):
            raise ValueError("keystorage body slot is not empty")
        _p32(buf, 12, count + 1)
        _p32(buf, 0x20, (count + 1) * record)
    item = meta + target * meta_len
    at = header + target * record
    if at + record > boundary(buf) - ST2_FOOTER or any(buf[at + 524:at + record]):
        raise ValueError("invalid keystorage firmware key body")
    if target < count:
        old = bytes(buf[at:at + 524])
        old_index = _u32(buf, item + name_len)
        pub_key(old)
        if zlib.crc32(old) != old_index or index in indexes - {old_index}:
            raise ValueError("invalid keystorage firmware key")
    buf[item:item + name_len] = b"fw_key" + bytes(name_len - 6)
    _p32(buf, item + name_len, index)
    _p32(buf, item + name_len + 4, 4)
    buf[at:at + 524] = pub
    return at
