"""حلقة الإثبات الذاتي: البصمة المحسوبة = البصمة المرصودة من الحزمة المبنية."""
import pytest

from modules.evasion.ja4_mutator import (
    TLSProfile, craft_client_hello, ja4, ja4_of_hello, parse_client_hello,
    verify_mutation,
)
from modules.evasion.fingerprint_plus import ja4h, ja4s, parse_server_hello


@pytest.mark.parametrize("sni", [True, False])
def test_ja4_prefix_structure(profile_dict, sni):
    p = TLSProfile.from_dict(profile_dict)
    fp = ja4(p.tls_version, sni, p.ciphers, p.extensions, p.sigalgs, p.alpn)
    a, b, c = fp.split("_")
    assert len(a) == 10
    assert a[0] == "t"
    assert a[1:3] == "13"
    assert a[3] == ("d" if sni else "i")
    assert a[4:6].isdigit() and a[6:8].isdigit()
    assert len(b) == 12 and len(c) == 12
    assert all(ch in "0123456789abcdef" for ch in b + c)


def test_grease_excluded_from_counts_and_hashes():
    fp_plain = ja4("13", True, [1301, 1302], [0, 10], [1027], ["h2"])
    fp_grease = ja4("13", True, [0x0a0a, 1301, 1302], [0x0a0a, 0, 10],
                    [1027], ["h2"])
    assert fp_plain == fp_grease          # GREASE لا يغيّر شيئاً


def test_craft_parse_roundtrip(profile_dict):
    p = TLSProfile.from_dict(profile_dict)
    hello = craft_client_hello(p, "example.com")
    parsed = parse_client_hello(hello)
    assert parsed["version"] == "13"
    assert parsed["alpn"][0] == "h2"
    assert parsed["sigalgs"] == p.sigalgs
    assert 0x0a0a in parsed["ciphers"]    # GREASE حاضرة في الحزمة الفعلية


def test_verify_mutation_self_consistency(profile_dict):
    p = TLSProfile.from_dict(profile_dict)
    ok, observed, expected = verify_mutation(p, "example.com")
    assert ok, f"observed={observed} expected={expected}"
    assert observed == expected


def test_parse_client_hello_real_world_vectors():
    """متجه معروف: JA4 لكروم حقيقي (t13d1516h2_...) يجب أن يُحسب بمطابقة
    العدّادين 15/16. البصمة الدقيقة تعتمد على قائمة التشفير الفعلية."""
    p = TLSProfile.from_dict(PROFILE_DICT)
    fp = p.ja4()
    assert fp.startswith("t13d1516h2_")
    assert len(fp) == 10 + 1 + 12 + 1 + 12


def test_ja4h_format():
    fp = ja4h("GET", "HTTP/2", "/api/users", [("host", "x.com"), ("accept", "*/*")],
              pseudo=[(":method", "get"), (":path", "/api/users")])
    a, b, c = fp.split("_")
    assert a.startswith("get2")           # method+version
    assert len(b) == 12 and len(c) == 12


def test_ja4s_server_hello_roundtrip(profile_dict):
    p = TLSProfile.from_dict(profile_dict)
    # نبني ServerHello اصطناعياً: TLS1.3 + cipher 0x1302 + امتدادين
    import struct
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"            # version+random+sid_len
    body += struct.pack(">H", 0x1302) + b"\x00"            # cipher+compression
    exts = struct.pack(">HH", 0x002b, 2) + b"\x03\x04" + struct.pack(">HH", 0x0016, 0)
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs

    server = parse_server_hello(record)
    assert server is not None
    assert server["cipher"] == 0x1302
    assert server["version"] == "12"      # 0x0303
    fp = ja4s(server, sni=True, alpn=["h2"])
    assert fp.startswith("s12d")
