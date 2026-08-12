"""محرك التخفي العميق: تزوير بصمة TLS (JA4) على مستوى الحزمة.

المرجع: مواصفة FoxIO JA4 — https://github.com/FoxIO-LLC/ja4

JA4 = {proto}{version}{SNI}{cc:02d}{ec:02d}{alpn_first_last}
      _{sha256(sorted ciphers)[:12]}_{sha256(sorted exts + sigalgs)[:12]}

قيم GREASE مستثناة من العد والتجزئة. SNI: d=موجود، i=غائب.
"""
import hashlib
import os
import random
import socket
import struct
from dataclasses import dataclass, field

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

VERSION_CODES = {
    b"\x03\x04": "13", b"\x03\x03": "12", b"\x03\x02": "11",
    b"\x03\x01": "10", b"\x03\x00": "30",
}

IMPERSONATE_MAP = {  # family -> أقرب سلسلة impersonate يدعمها curl_cffi
    "chrome": "chrome124",
    "firefox": "firefox127",
    "safari": "safari17_0",
    "edge": "edge124",
}

# مجموعة سلامة للطرافات (supported_groups) في ClientHello الحقيقي
GROUPS = [0x001d, 0x0017, 0x0018, 0x0019, 0x001a]          # x25519, p256, p384, p521, x448


def _h12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4(version: str, sni: bool, ciphers: list[int], extensions: list[int],
        sigalgs: list[int], alpn: list[str]) -> str:
    """حساب بصمة JA4 حسب مواصفة FoxIO — قيم GREASE مستثناة من العد والتجزئة."""
    c = sorted(x for x in ciphers if x not in GREASE)
    e = sorted(x for x in extensions if x not in GREASE)
    s = sorted(x for x in sigalgs if x not in GREASE)
    cc = min(len(c), 99)
    ec = min(len(e), 99)
    a0 = (alpn[0][:1] if alpn else "?")
    a1 = (alpn[-1][:1] if alpn else "?")
    c_hash = _h12("".join(f"{x:04x}" for x in c))
    es_hash = _h12("".join(f"{x:04x}" for x in e) + "".join(f"{x:04x}" for x in s))
    return (f"t{version}{'d' if sni else 'i'}{cc:02d}{ec:02d}{a0}{a1}"
            f"_{c_hash}_{es_hash}")


def ext(t: int, data: bytes) -> bytes:
    """ترميز امتداد TLS: (type:2 + length:2 + data)."""
    return struct.pack(">HH", t, len(data)) + data


@dataclass
class TLSProfile:
    name: str
    family: str
    impersonate: str
    ua: str
    platform: str
    tls_version: str = "13"
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    sigalgs: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    grease: bool = True
    headers: dict = field(default_factory=dict)
    http2: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "TLSProfile":
        """بناء بروفايل من قاموس config/network_profiles.json."""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def ja4(self) -> str:
        """البصمة النظرية المتوقعة لهذا البروفايل."""
        return ja4(self.tls_version, True, self.ciphers,
                   self.extensions, self.sigalgs, self.alpn)

    def get(self, key: str, default=None):
        """توافق مع أسلوب dict.get المستخدم في core/orchestrator.py."""
        return getattr(self, key, default)


class FingerprintBank:
    """مكتبة بصمات TLS: تحميل من config/network_profiles.json وتقديم بصمة مطفَّرة لكل خلية."""

    def __init__(self, profiles: list[dict]):
        self.profiles = [TLSProfile.from_dict(p) for p in profiles]
        if not self.profiles:
            raise ValueError("لا توجد بصمات TLS — تحقق من config/network_profiles.json")

    def mutated_profile(self) -> TLSProfile:
        """اختيار بصمة عشوائية مع تطفير خفيف: خلط ترتيب السويتات والامتدادات."""
        prof = random.choice(self.profiles)
        return TLSProfile(
            name=prof.name, family=prof.family, impersonate=prof.impersonate,
            ua=prof.ua, platform=prof.platform, tls_version=prof.tls_version,
            ciphers=random.sample(prof.ciphers, len(prof.ciphers)),
            extensions=random.sample(prof.extensions, len(prof.extensions)),
            sigalgs=random.sample(prof.sigalgs, len(prof.sigalgs)),
            alpn=list(prof.alpn), grease=prof.grease,
            headers=dict(prof.headers), http2=dict(prof.http2),
        )


def impersonate_for(profile: TLSProfile) -> str:
    """أقرب سلسلة impersonate تدعمها curl_cffi حسب عائلة المتصفح."""
    return IMPERSONATE_MAP.get(profile.family, "chrome124")


def craft_client_hello(profile: TLSProfile, server_name: str = "example.com") -> bytes:
    """بناء ClientHello حقيقي المظهر من بروفايل TLS (للإثبات الذاتي والفحص الخارجي)."""
    # SNI (0x0000): server_name_list = [type:1][len:2][name]
    sni = b"".join(bytes([len(l)]) + l.encode() for l in server_name.split("."))
    # ALPN (0x0010): list = [len:2][proto:len+data]*
    alpn_list = b"".join(bytes([len(p)]) + p.encode() for p in profile.alpn)
    alpn_ext = struct.pack(">H", len(alpn_list)) + alpn_list
    # signature_algorithms (0x000d): vector = [len:2][sigalg:2]*
    sigs = b"".join(struct.pack(">H", s) for s in profile.sigalgs)
    sigs_ext = struct.pack(">H", len(sigs)) + sigs
    # supported_versions (0x002b): vector = [len:1][version:2]
    vers = b"\x03\x04" if profile.tls_version == "13" else b"\x03\x03"
    vers_ext = bytes([len(vers)]) + vers

    exts = list(profile.extensions)
    body = b""
    body += b"\x03\x03"                        # legacy_version (سجل TLS 1.2)
    body += os.urandom(32)                     # random
    body += b"\x00"                            # session_id (فارغ)
    cs = b"".join(struct.pack(">H", c) for c in profile.ciphers)
    body += struct.pack(">H", len(cs)) + cs    # cipher_suites
    body += b"\x01\x00"                        # compression_methods

    ep = b""
    # SNI
    ep += ext(0x0000, struct.pack(">H", len(sni) + 3) + b"\x00" + struct.pack(">H", len(sni)) + sni)
    # ALPN
    ep += ext(0x0010, alpn_ext)
    # signature_algorithms
    ep += ext(0x000d, sigs_ext)
    # supported_versions
    ep += ext(0x002b, vers_ext)
    # key_share (0x0033): GREASE + x25519 dummy
    ks = b"\x00\x1d" + struct.pack(">H", 32) + os.urandom(32)
    ep += ext(0x0033, struct.pack(">H", 2 + len(ks)) + struct.pack(">H", 0x0a0a) + b"\x00\x00" + ks)
    # ec_point_formats (0x000a)
    ep += ext(0x000a, b"\x01\x00")
    # psk_key_exchange_modes (0x002d)
    ep += ext(0x002d, b"\x01\x00")
    # أي امتدادات أخرى من البروفايل: نص فارغ (تُحسب في JA4 دون كسر الحزمة)
    for t in exts:
        if t not in (0x0000, 0x0010, 0x000d, 0x002b, 0x0033, 0x000a, 0x002d, 0x0a0a):
            ep += ext(t, b"")

    body += struct.pack(">H", len(ep)) + ep
    hs = b"\x01" + len(body).to_bytes(3, "big") + body          # handshake: ClientHello
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs     # record
    return rec


def parse_client_hello(data: bytes) -> dict:
    """عكس الصياغة: استخراج المعاملات من ClientHello لفحص JA4 المار على الشبكة."""
    assert data[0] == 0x16, "ليست حزمة TLS handshake"
    hs_len = int.from_bytes(data[3:5], "big")
    hs = data[5:5 + hs_len]
    assert hs[0] == 0x01, "ليست ClientHello"
    b = hs[4:]
    version = VERSION_CODES.get(b[0:2], "??")
    pos = 2 + 32
    sid_len = b[pos]; pos += 1 + sid_len
    cs_len = int.from_bytes(b[pos:pos + 2], "big"); pos += 2
    ciphers = [int.from_bytes(b[i:i + 2], "big") for i in range(pos, pos + cs_len, 2)]
    pos += cs_len
    cm_len = b[pos]; pos += 1 + cm_len
    exts_len = int.from_bytes(b[pos:pos + 2], "big"); pos += 2
    extensions, sigalgs, alpn, versions = [], [], [], []
    end = pos + exts_len
    while pos < end:
        t = int.from_bytes(b[pos:pos + 2], "big")
        l = int.from_bytes(b[pos + 2:pos + 4], "big")
        d = b[pos + 4:pos + 4 + l]
        extensions.append(t)
        if t == 0x000d and len(d) >= 2:
            sigalgs = [int.from_bytes(d[i:i + 2], "big") for i in range(0, len(d), 2)]
        elif t == 0x0010 and len(d) >= 2:
            alpn = []
            i, n = 2, int.from_bytes(d[0:2], "big")
            while i < 2 + n and i < len(d):
                ln = d[i]; i += 1
                alpn.append(d[i:i + ln].decode(errors="replace")); i += ln
        elif t == 0x002b and len(d) >= 1:
            n = d[0]; versions = [int.from_bytes(d[1 + j:3 + j], "big") for j in range(0, n, 2)]
        pos += 4 + l
    if versions:
        version = VERSION_CODES.get(bytes(versions[:1]) and b"\x03" + versions[0].to_bytes(1, "big"), version) if versions[0] <= 0x0304 else version
    return {"version": version, "ciphers": ciphers, "extensions": extensions,
            "sigalgs": sigalgs, "alpn": alpn}


def ja4_of_hello(data: bytes) -> str:
    p = parse_client_hello(data)
    return ja4(p["version"], True, p["ciphers"], p["extensions"], p["sigalgs"], p["alpn"])


def verify_mutation(profile: TLSProfile, server_name: str = "example.com") -> bool:
    """حلقة الإثبات الذاتية: ما يُبنى على الشبكة = ما يُحسب نظرياً."""
    hello = craft_client_hello(profile, server_name)
    observed = ja4_of_hello(hello)
    expected = profile.ja4()
    return observed == expected, observed, expected


def probe_ja4_remote(host: str, port: int, profile: TLSProfile, timeout: float = 6.0) -> str:
    """إرسال ClientHello مطفَّر عبر socket خام لمخدم TLS حقيقي (تحقق خارجي)."""
    hello = craft_client_hello(profile, host)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(hello)
        try:
            s.settimeout(timeout)
            resp = s.recv(2048)
            return ja4_of_hello(hello) + " | server_acked=" + str(len(resp) > 0)
        except socket.timeout:
            return ja4_of_hello(hello) + " | server_acked=False"


# ============================================================== حصاد بصمات حقيقية
class CaptureListener:
    """التقاط ClientHello من متصفح حقيقي تحكم به (scapy) لإثراء المكتبة ببصمات حيّة."""

    def __init__(self, iface: str = "lo", host: str = "127.0.0.1", port: int = 443):
        self.iface, self.host, self.port = iface, host, port

    def capture_one(self, timeout: int = 30) -> dict:
        try:
            from scapy.all import IP, TCP, sniff  # استيراد متأخر: لا يتطلب صلاحيات عند الاستيراد
        except ImportError as exc:
            # تصحيح التوافقية (Termux/Linux): رسالة واضحة بدل انهيار صامت
            raise RuntimeError(
                "scapy غير مثبت — ميزة --capture-profile غير متاحة.\n"
                "  Linux : pip install scapy\n"
                "  Termux: pkg install python-scapy  (يلزم root/صلاحيات raw socket للالتقاط)"
            ) from exc

        captured = {}

        def _cb(pkt):
            if TCP in pkt and pkt[TCP].dport == self.port and pkt[TCP].payload:
                raw = bytes(pkt[TCP].payload)
                if raw[0] == 0x16:                      # TLS record
                    try:
                        captured.update(parse_client_hello(raw))
                        captured["raw_len"] = len(raw)
                        return True
                    except Exception:
                        return False
            return False

        sniff(iface=self.iface, prn=lambda p: _cb(p), store=False,
              filter=f"tcp and host {self.host} and port {self.port}",
              timeout=timeout, stop_filter=lambda p: bool(captured))
        return captured
