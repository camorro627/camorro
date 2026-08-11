"""المحرك الموسّع: JA4H / JA4X / JA4S / JARM + مدقق اتساق الملفات التعريفية.

المراجع:
  - JA4H/JA4X/JA4S: مواصفات FoxIO (technical_details/JA4H.md, JA4X.md)
  - JARM: Salesforce Engineering — 10 ClientHello مخصصة + تجزئة هجينة 62 حرفاً
"""
import asyncio
import hashlib
import os
import random
import socket
import struct

from .ja4_mutator import GREASE, VERSION_CODES, _h12

# ============================================================== JA4H — HTTP
def ja4h(method: str, http_version: str, path: str,
         headers: list[tuple[str, str]],
         pseudo: list[tuple[str, str]] | None = None) -> str:
    """بصمة طلب HTTP حسب مواصفة FoxIO:
    {method:3}{version:1}{path_len:02d}{header_count:02d}_{name_hash}_{value_hash}
    - method: أول 3 أحرف صغيرة (get/pos/hea/pat...)
    - version: '1' لـ HTTP/1.x، '2' لـ HTTP/2
    - path_len: طول المسار دون الاستعلام (حد 99)
    - header_count: عدد الرؤوس — يتضمن pseudo-headers في HTTP/2 (حد 99)
    - name_hash/value_hash: sha256 بترتيب الإرسال، مفصولة بفواصل (12 حرفاً)
    """
    m = method[:3].lower()
    v = "2" if http_version.startswith("2") else "1"
    plen = min(len(path), 99)
    hdrs = list(pseudo or []) + list(headers)
    hc = min(len(hdrs), 99)
    names = ",".join(k.lower() for k, _ in hdrs)
    values = ",".join(val for _, val in hdrs)
    return f"{m}{v}{plen:02d}{hc:02d}_{_h12(names)}_{_h12(values)}"


def ja4h_of_headers(method: str, http_version: str, path: str, headers: dict) -> str:
    return ja4h(method, http_version, path, list(headers.items()))


# ============================================================== JA4X — الامتدادات
def ja4x(extensions: list[tuple[int, bytes]]) -> str:
    """بصمة محتوى امتدادات ClientHello: {order_hash}_{value_hash}
    order_hash: أنواع الامتدادات بترتيب الظهور (GREASE مستثنى)
    value_hash: قيم الامتدادات بترتيب الظهور (hex مفصولة بفواصل)
    """
    exts = [(t, d) for t, d in extensions if t not in GREASE]
    order = ",".join(f"{t:04x}" for t, _ in exts)
    values = ",".join(d.hex() for _, d in exts)
    return f"{_h12(order)}_{_h12(values)}"


# ============================================================== JA4S — استجابة الخادم
def parse_server_hello(data: bytes) -> dict | None:
    """استخراج version/cipher/extensions من ServerHello خام."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    hs_len = int.from_bytes(data[3:5], "big")
    hs = data[5:5 + hs_len]
    if len(hs) < 4 or hs[0] != 0x02:
        return None
    b = hs[4:]
    version = VERSION_CODES.get(b[0:2], "??")
    pos = 2 + 32
    sid_len = b[pos]; pos += 1 + sid_len
    cipher = int.from_bytes(b[pos:pos + 2], "big"); pos += 2
    pos += 1                                   # compression_method
    extensions: list[tuple[int, bytes]] = []
    if pos + 2 <= len(b):
        elen = int.from_bytes(b[pos:pos + 2], "big"); pos += 2
        end = min(pos + elen, len(b))
        while pos + 4 <= end:
            t = int.from_bytes(b[pos:pos + 2], "big")
            l = int.from_bytes(b[pos + 2:pos + 4], "big")
            extensions.append((t, b[pos + 4:pos + 4 + l]))
            pos += 4 + l
    return {"version": version, "cipher": cipher, "extensions": extensions}


def ja4s(server: dict, sni: bool = True, alpn: list[str] | None = None) -> str:
    """بصمة استجابة الخادم: s{version}{sni}{alpn}_{cipher_hash}_{ext_hash}
    TLS1.3: cipher_hash = تجزئة التشفير المختار فقط. TLS1.2: تجزئة القائمة.
    """
    version = server["version"]
    alpn_tag = "00"
    if alpn:
        first = alpn[0]
        alpn_tag = (first[0] + first[-1]) if len(first) >= 2 else first + "0"
    c = _h12(f"{server['cipher']:04x}")
    exts = [t for t, _ in server["extensions"] if t not in GREASE]
    e = _h12(",".join(f"{x:04x}" for x in sorted(exts)))
    return f"s{version}{'d' if sni else 'i'}{alpn_tag}_{c}_{e}"


# ============================================================== JARM — ماسح نشط
class JARMScanner:
    """بصمة TLS نشطة للخادم (تحديد WAF/CDN/بنية C2 خلف الهدف).

    البصمة: 62 حرفاً =
      30 الأولى: تجزئة ضبابية (sha256 لكل استجابة، أول 3 أحرف hex) —
                 '000' عند رفض التفاوض أو عدم الاستجابة
      32 الأخيرة: SHA256 مبتور للامتدادات التراكمية من كل ServerHello
                  (دون بيانات x509 — امتدادات ServerHello فقط)

    ملاحظة: الحزم أدناه تعكس التصميم الموثق في README الخاص بـ salesforce/jarm
    (تنويع إصدارات TLS/قوائم التشفير/الامتدادات/GREASE). لمن يريد تطابقاً
    بايت-ببايت مع الأداة الأصلية، استبدل PACKETS بالقائمة المرجعية من مستودعها.
    """

    PACKETS: list[dict] = [
        # إصدارات حديثة + امتدادات كاملة
        {"tls_version": 0x0304, "grease": False,
         "ciphers": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                     0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
         "extensions": [0x0000, 0x001b, 0x0023, 0x0010, 0x0017, 0x0033, 0x000d,
                        0x0005, 0x0012, 0x7550, 0x002b, 0x0015, 0x000a, 0x0029, 0x0016]},
        # TLS 1.2 + امتدادات كاملة
        {"tls_version": 0x0303, "grease": False,
         "ciphers": [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                     0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
         "extensions": [0x0000, 0x0010, 0x000d, 0x002b, 0x0015, 0x000a]},
        # TLS 1.2 بلا امتدادات
        {"tls_version": 0x0303, "grease": False,
         "ciphers": [0xc02b, 0xc02f, 0xc013, 0xc014, 0x002f, 0x0035],
         "extensions": []},
        # TLS 1.1
        {"tls_version": 0x0302, "grease": False,
         "ciphers": [0xc013, 0xc014, 0x002f, 0x0035, 0x000a],
         "extensions": [0x0000, 0x000a, 0x0010, 0x000d]},
        # TLS 1.0
        {"tls_version": 0x0301, "grease": False,
         "ciphers": [0xc013, 0xc014, 0x002f, 0x0035, 0x000a],
         "extensions": [0x0000, 0x000a, 0x0010]},
        # SSLv3 (تشفيرات قديمة)
        {"tls_version": 0x0300, "grease": False,
         "ciphers": [0x000a, 0x0035, 0x002f, 0x0005, 0x0004],
         "extensions": [0x0000, 0x000a]},
        # تشفيرات هجينة
        {"tls_version": 0x0303, "grease": False,
         "ciphers": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc013, 0xc014,
                     0x002f, 0x0035, 0x000a],
         "extensions": [0x0000, 0x000a, 0x0010, 0x000d]},
        # GREASE فقط
        {"tls_version": 0x0303, "grease": True,
         "ciphers": [0xc02b, 0xc02f, 0xc013, 0xc014, 0x002f, 0x0035],
         "extensions": []},
        # GREASE + امتدادات
        {"tls_version": 0x0303, "grease": True,
         "ciphers": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc013, 0xc014],
         "extensions": [0x0000, 0x001b, 0x0023, 0x0010, 0x0017, 0x0033, 0x000d]},
        # TLS 1.3 بدون SNI
        {"tls_version": 0x0304, "grease": False,
         "ciphers": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                     0xcca9, 0xcca8, 0xc013, 0xc014],
         "extensions": [0x001b, 0x0023, 0x0010, 0x0017, 0x0033, 0x000d,
                        0x0005, 0x0012, 0x002b, 0x0015, 0x000a, 0x0029]},
    ]

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    # ------------------------------------------------------------ بناء الحزم
    def build_client_hello(self, pkt: dict, server_name: str = "") -> bytes:
        ciphers = list(pkt["ciphers"])
        exts = list(pkt["extensions"])
        if pkt.get("grease"):
            ciphers = [0x0a0a] + ciphers
            exts = [0x0a0a] + exts
        body = pkt["tls_version"].to_bytes(2, "big") + os.urandom(32) + b"\x00"
        body += struct.pack(">H", len(ciphers)) + b"".join(
            struct.pack(">H", c) for c in ciphers)
        body += b"\x01\x00"                                   # compression: null

        def ext(t: int, d: bytes) -> bytes:
            return struct.pack(">HH", t, len(d)) + d

        ep = b""
        if server_name:
            sni = b"\x00" + struct.pack(">H", len(server_name)) + server_name.encode()
            ep += ext(0x0000, b"\x00" + struct.pack(">H", len(sni)) + sni)
        if 0x0010 in exts:
            adata = b"\x00\x02h2"
            ep += ext(0x0010, struct.pack(">H", len(adata)) + adata)
        if 0x000d in exts:
            sg = b"".join(struct.pack(">H", s) for s in (0x0403, 0x0804, 0x0401, 0x0503, 0x0201))
            ep += ext(0x000d, struct.pack(">H", len(sg)) + sg)
        if 0x002b in exts:
            vs = b"".join(struct.pack(">H", v) for v in (0x0304, 0x0303, 0x0302, 0x0301))
            ep += ext(0x002b, bytes([len(vs)]) + vs)
        if 0x0033 in exts:
            ks = b"\x00\x1d" + struct.pack(">H", 32) + os.urandom(32)
            ep += ext(0x0033, struct.pack(">H", 2 + len(ks)) + struct.pack(">H", 0x0a0a) + b"\x00\x00" + ks)
        for t in exts:                                        # بقية الامتدادات: نص فارغ
            if t not in (0x0000, 0x0010, 0x000d, 0x002b, 0x0033, 0x0a0a):
                ep += ext(t, b"")
        body += struct.pack(">H", len(ep)) + ep
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    # ------------------------------------------------------------ التجزئة
    @staticmethod
    def segment(resp: bytes) -> str:
        """3 أحرف لكل استجابة؛ '000' للرفض/انقطاع."""
        return "000" if not resp else hashlib.sha256(resp).hexdigest()[:3]

    # ------------------------------------------------------------ المسح
    async def _handshake(self, host: str, port: int, pkt: dict) -> bytes:
        hello = self.build_client_hello(pkt, server_name=host)
        loop = asyncio.get_running_loop()

        def _sync() -> bytes:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                s.sendall(hello)
                s.settimeout(self.timeout)
                try:
                    return s.recv(4096)
                except socket.timeout:
                    return b""

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _sync), self.timeout + 2)
        except Exception:
            return b""

    async def scan(self, host: str, port: int = 443) -> str:
        """البصمة الكاملة 62 حرفاً."""
        hellos: list[bytes] = []
        for pkt in self.PACKETS:
            hellos.append(await self._handshake(host, port, pkt))
        first30 = "".join(self.segment(r) for r in hellos)
        exts = b""
        for r in hellos:
            sh = parse_server_hello(r)
            if sh:
                exts += b"".join(d for _, d in sh["extensions"])
        last32 = hashlib.sha256(exts).hexdigest()[:32]
        return first30 + last32

    async def scan_many(self, hosts: list[tuple[str, int]], concurrency: int = 8) -> dict:
        """مسح متوازٍ (حد concurrency) لمجموعة أهداف."""
        sem = asyncio.Semaphore(concurrency)

        async def _one(h, p):
            async with sem:
                return (h, p, await self.scan(h, p))

        results = await asyncio.gather(*(_one(h, p) for h, p in hosts))
        return {f"{h}:{p}": fp for h, p, fp in results}


# ============================================================== مدقق الاتساق
class ProfileLinter:
    """مدقق: هل بصمة TLS متسقة مع رؤوس HTTP وسلوك العائلة؟
    يُستدعى قبل اعتماد أي ملف تعريف مطفَّر — أي تناقض يفضح الانتحال أمام WAF.
    """

    @staticmethod
    def lint(profile) -> list[str]:
        issues: list[str] = []
        ua = profile.ua.lower()
        fam = profile.family
        fam_checks = {
            "chrome": "chrome/", "firefox": "firefox/",
            "safari": ("safari/" , "version/"), "edge": "edg/",
        }
        need = fam_checks.get(fam)
        if need:
            if isinstance(need, tuple):
                if not any(n in ua for n in need):
                    issues.append(f"UA لا يطابق عائلة {fam}")
            elif need not in ua:
                issues.append(f"UA لا يطابق عائلة {fam}")

        plat = profile.platform.lower()
        sch = (profile.headers.get("sec-ch-ua-platform") or "").lower().strip('"')
        if sch and plat and plat not in sch:
            issues.append("sec-ch-ua-platform لا يطابق profile.platform")

        if profile.http2 and "h2" not in (profile.alpn or []):
            issues.append("إعدادات HTTP/2 موجودة بدون ALPN h2")

        if not (10 <= len(profile.ciphers) <= 24):
            issues.append(f"عدد تشفيرات غير معتاد: {len(profile.ciphers)}")
        if not (8 <= len(profile.extensions) <= 24):
            issues.append(f"عدد امتدادات غير معتاد: {len(profile.extensions)}")
        if not profile.sigalgs:
            issues.append("signature_algorithms فارغ")
        return issues
