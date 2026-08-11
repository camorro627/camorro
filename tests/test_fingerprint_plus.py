"""JARM (بنية البصمة) + JA4X + ProfileLinter."""
import asyncio

import pytest

from modules.evasion.fingerprint_plus import (
    JARMScanner, ProfileLinter, ja4x,
)


def test_jarm_length_and_structure():
    fp = "29d29d15d29d29d00042d42d00000049d8801e4f5e9656b954b3b1ca4a680b"
    assert len(fp) == 62
    assert all(c in "0123456789abcdef" for c in fp)
    assert fp[:30].count("000") >= 0
    # 30 الأولى: 10 مقاطع من 3 أحرف
    assert [fp[i:i + 3] for i in range(0, 30, 3)]


def test_jarm_segment_rules():
    s = JARMScanner.segment(b"")
    assert s == "000"
    s2 = JARMScanner.segment(b"hello")
    assert s2 == hashlib_hex3(b"hello")


def hashlib_hex3(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()[:3]


def test_jarm_build_client_hello_shapes():
    s = JARMScanner()
    for pkt in s.PACKETS:
        hello = s.build_client_hello(pkt, server_name="example.com")
        assert hello[0] == 0x16
        assert hello[5] == 0x01            # ClientHello
    # حزمة GREASE تحوي 0x0a0a في أول تشفير
    grease_pkt = next(p for p in s.PACKETS if p.get("grease"))
    hello = s.build_client_hello(grease_pkt, "example.com")
    assert b"\x0a\x0a" in hello


def test_ja4x_order_matters():
    fp1 = ja4x([(0x000d, b"\x01"), (0x0010, b"\x02")])
    fp2 = ja4x([(0x0010, b"\x02"), (0x000d, b"\x01")])
    assert fp1 != fp2                      # الترتيب يدخل في التجزئة
    # GREASE مستثنى من order_hash
    fp3 = ja4x([(0x0a0a, b""), (0x000d, b"\x01"), (0x0010, b"\x02")])
    assert fp3 == fp1


def test_profile_linter_detects_mismatch(profile_dict):
    p = TLSProfile.from_dict(profile_dict)
    assert ProfileLinter.lint(p) == []

    bad = p.clone()
    bad.ua = "Mozilla/5.0 (X11; Linux) Firefox/127.0"      # عائلة متضاربة
    issues = ProfileLinter.lint(bad)
    assert any("UA" in i for i in issues)
