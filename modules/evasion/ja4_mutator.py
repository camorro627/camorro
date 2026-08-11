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
        sigalgs: list[int], alpn: list[str], proto: str = "t") -> str:
    """حساب JA4 كاملاً حسب المواصفة."""
    ciphers = [c for c in ciphers if c not in GREASE]
    extensions = [e for e in extensions if e not in GREASE]
    cc = f"{len(ciphers):02d}"
    ec = f"{len(extensions):02d}"
    if alpn:
        first = alpn[0]
        alpn_tag = (first[0] + first[-1]) if len(first) >= 2 else (first + "0")
    else:
        alpn_tag = "00"
    sni_tag = "d" if sni else "i"

    b = _h12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    c_input = ",".join(f"{e:04x}" for e in sorted(extensions)) + "_" + ",".join(
        f"{s:04x}" for s in sigalgs)                      # sigalgs بترتيب الإرسال
    c = _h12(c_input)
    return f"{proto}{version}{sni_tag}{cc}{ec}{alpn_tag}_{b}_{c}"


@dataclass
class TLSProfile:
    name: str
    family: str
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
        return cls(
            name=d["name"], family=d["family"], ua=d["ua"], platform=d.get("platform", ""),
            tls_version=d.get("tls_version", "13"), ciphers=list(d["ciphers"]),
            extensions=list(d["extensions"]), sigalgs=list(d["sigalgs"]),
            alpn=list(d.get("alpn", ["h2", "http/1.1"])), grease=d.get("grease", True),
            headers=d.get("headers", {}), http2=d.get("http2", {}),
        )

    def ja4(self) -> str:
        return ja4(self.tls_version, True, self.ciphers, self.extensions,
                   self.sigalgs, self.alpn)

    def clone(self) -> "TLSProfile":
        return TLSProfile(
            name=self.name, family=self.family, ua=self.ua, platform=self.platform,
            tls_version=self.tls_version, ciphers=list(self.ciphers),
            extensions=list(self.extensions), sigalgs=list(self.sigalgs),
            alpn=list(self.alpn), grease=self.grease,
            headers=dict(self.headers), http2=dict(self.http2),
        )


def impersonate_for(profile: dict | TLSProfile) -> str:
    fam = profile.family if isinstance(profile, TLSProfile) else profile.get("family", "chrome")
    return IMPERSONATE_MAP.get(fam, "chrome124")


class FingerprintBank:
    """مكتبة بصمات + مولّد طفرات يبقي الناتج داخل فضاء المتصفحات الحقيقي."""

    def __init__(self, raw_profiles: list[dict], rng: random.Random | None = None):
        self.rng = rng or random
        self.base = [TLSProfile.from_dict(d) for d in raw_profiles]

    def pick(self) -> TLSProfile:
        return self.rng.choice(self.base).clone()

    # ------------------------------------------------------------ mutation ops
    def _mutate_ciphers(self, p: TLSProfile, intensity: float) -> None:
        """قص/خلط/إعادة GREASE داخل حدود معقولة."""
        if p.grease and self.rng.random() < 0.35:
            p.ciphers = [self.rng.choice(sorted(GREASE))] + p.ciphers
        k = max(1, int(len(p.ciphers) * intensity * 0.4))
        if k > 1:
            tail = p.ciphers[k:]
            self.rng.shuffle(tail)
            p.ciphers = p.ciphers[:k] + tail
        # إسقاط تشفير قديم بشكل عشوائي (يبقي TLS1.3 دائماً)
        if len(p.ciphers) > 12 and self.rng.random() < 0.5:
            drop = [c for c in p.ciphers if c in (0x000a, 0x00ff, 0x5600)]
            for c in drop:
                p.ciphers.remove(c)

    def _mutate_extensions(self, p: TLSProfile, intensity: float) -> None:
        benign = [0x000b, 0x000f, 0x0012, 0x0015, 0x0016, 0x0017, 0x0022, 0x0023]
        if self.rng.random() < 0.4 and p.extensions:
            p.extensions.pop(self.rng.randrange(len(p.extensions)))
        if self.rng.random() < 0.3:
            extra = self.rng.choice(benign)
            pos = self.rng.randrange(len(p.extensions) + 1)
            p.extensions.insert(pos, extra)
        if p.grease and self.rng.random() < 0.25:
            p.extensions.insert(0, self.rng.choice(sorted(GREASE)))

    def _mutate_sigalgs(self, p: TLSProfile, intensity: float) -> None:
        if len(p.sigalgs) > 4 and self.rng.random() < 0.5:
            self.rng.shuffle(p.sigalgs)
        if self.rng.random() < 0.3:
            p.sigalgs = p.sigalgs[:max(4, len(p.sigalgs) - 2)]

    def _mutate_alpn(self, p: TLSProfile) -> None:
        if len(p.alpn) > 1 and self.rng.random() < 0.2:
            self.rng.shuffle(p.alpn)

    # ------------------------------------------------------------ public API
    def mutated_profile(self, intensity: float | None = None) -> TLSProfile:
        p = self.pick()
        intensity = intensity if intensity is not None else self.rng.uniform(0.2, 0.65)
        self._mutate_ciphers(p, intensity)
        self._mutate_extensions(p, intensity)
        self._mutate_sigalgs(p, intensity)
        self._mutate_alpn(p)
        return p

    def clone_ja4(self, target_ja4: str) -> TLSProfile:
        """تقليد بصمة محددة: اختيار أقرب ملف تعريف ثم طفرة حتى المطابقة."""
        for _ in range(300):
            p = self.mutated_profile(intensity=0.15)
            if p.ja4() == target_ja4:
                return p
        raise ValueError(f"تعذر استنساخ JA4={target_ja4} من المكتبة الحالية")


# ============================================================== صياغة الحزم
def craft_client_hello(profile: TLSProfile, server_name: str) -> bytes:
    """بناء ClientHello يدوياً (TLS 1.3-capable) — للتحقق أو القنوات غير HTTP."""
    ciphers = list(profile.ciphers)
    exts = list(profile.extensions)
    if profile.grease:
        ciphers = [0x0a0a] + ciphers
        exts = [0x0a0a] + exts

    body = b"\x03\x03" + os.urandom(32) + b"\x00"
    body += struct.pack(">H", len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00"                                   # compression_methods: null

    def ext(t: int, data: bytes) -> bytes:
        return struct.pack(">HH", t, len(data)) + data

    ep = b""
    # SNI (0x0000)
    sni = b"\x00" + struct.pack(">H", len(server_name)) + server_name.encode()
    ep += ext(0x0000, b"\x00" + struct.pack(">H", len(sni)) + sni)
    # supported_groups (0x0010)
    gdata = b"".join(struct.pack(">H", g) for g in GROUPS)
    ep += ext(0x0010, struct.pack(">H", len(gdata)) + gdata)
    # signature_algorithms (0x000d)
    sdata = b"".join(struct.pack(">H", s) for s in profile.sigalgs)
    ep += ext(0x000d, struct.pack(">H", len(sdata)) + sdata)
    # supported_versions (0x002b)
    versions = [0x0304, 0x0303, 0x0302, 0x0301]
    vdata = b"".join(struct.pack(">H", v) for v in versions)
    ep += ext(0x002b, bytes([len(vdata)]) + vdata)
    # ALPN (0x0010)
    adata = b"".join(bytes([len(a)]) + a.encode() for a in profile.alpn)
    ep += ext(0x0010, struct.pack(">H", len(adata)) + adata)
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
        from scapy.all import IP, TCP, sniff  # استيراد متأخر: لا يتطلب صلاحيات عند الاستيراد

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
