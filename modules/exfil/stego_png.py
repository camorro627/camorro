"""إخفاء بيانات في LSB لصور PNG — تنفيذ خالص بالبايثون:
قراءة/كتابة صور PNG (تجزئة IDAT عبر zlib + CRC32) + تضمين/استخراج البتات.
يُتخطى بايت المرشح (filter byte) في بداية كل صف مسح ضوئي.
"""
import binascii
import struct
import zlib
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"
LEN_HDR = 4  # بادئة طول الحمولة (Big-Endian)


def _chunk(ctype: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + ctype + data
            + struct.pack(">I", binascii.crc32(ctype + data) & 0xFFFFFFFF))


def read_png(path: Path) -> tuple[int, int, int, bytes]:
    """(العرض، الارتفاع، القنوات، البايتات الخام) — RGB8/RGBA8 فقط، بدون interlacing."""
    data = Path(path).read_bytes()
    assert data[:8] == PNG_SIG, "ليست PNG صالحة"
    pos, idat, w, h, ch = 8, b"", 0, 0, 0
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + ln]
        if ctype == b"IHDR":
            w, h, depth, color, _c, _f, interlace = struct.unpack(">IIBBBBB", body)
            assert depth == 8 and color in (2, 6) and interlace == 0, "يدعم RGB8/RGBA8 فقط"
            ch = 3 if color == 2 else 4
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
        pos += 12 + ln
    return w, h, ch, zlib.decompress(idat)


def write_png(path: Path, w: int, h: int, channels: int, raw: bytes) -> None:
    color = 2 if channels == 3 else 6
    ihdr = struct.pack(">IIBBBBB", w, h, 8, color, 0, 0, 0)
    idat = zlib.compress(raw, 9)
    Path(path).write_bytes(
        PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))


def capacity(w: int, h: int, channels: int) -> int:
    """السعة بالبايت (ناقص بادئة الطول)."""
    return (w * h * channels) // 8 - LEN_HDR


def _pixel_indices(raw_len: int, w: int, h: int, channels: int):
    stride = 1 + w * channels                     # بايت المرشح + بكسل الصف
    for row in range(h):
        base = row * stride + 1
        yield from range(base, base + w * channels)


def _bits_of(data: bytes) -> list[int]:
    out = []
    for byte in data:
        for b in range(8):
            out.append((byte >> b) & 1)           # LSB أولاً
    return out


def _bytes_of(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in range(8):
            v |= bits[i + b] << b
        out.append(v)
    return bytes(out)


def embed_payload(cover: Path, out: Path, payload: bytes) -> int:
    w, h, ch, raw = read_png(cover)
    cap = capacity(w, h, ch)
    if len(payload) > cap:
        raise ValueError(f"الحمولة {len(payload)}B تتجاوز السعة {cap}B")
    data = bytearray(raw)
    bits = _bits_of(len(payload).to_bytes(LEN_HDR, "big") + payload)
    for idx, bit in zip(_pixel_indices(len(raw), w, h, ch), bits):
        data[idx] = (data[idx] & 0xFE) | bit
    write_png(out, w, h, ch, bytes(data))
    return len(payload)


def extract_payload(png: Path) -> bytes:
    w, h, ch, raw = read_png(png)
    indices = list(_pixel_indices(len(raw), w, h, ch))
    if len(indices) < 32:
        return b""
    bits = [raw[i] & 1 for i in indices]
    length = int.from_bytes(_bytes_of(bits[:32]), "big")
    need = 32 + length * 8
    if length == 0 or need > len(bits):
        return b""
    return _bytes_of(bits[32:need])
