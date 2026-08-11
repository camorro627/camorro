"""تحليل ملفات JS: استخراج النقاط (endpoints)، مكالمات API، خرائط المصدر
(source maps)، وأنماط الأسرار (مفاتيح AWS/JWT/API tokens)."""
import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field

STRING_RE = re.compile(r'''(["'`])((?:\\.|(?!\1).)*)\1''')
ENDPOINT_RE = re.compile(r"(?:['\"`])((?:/|https?://)[A-Za-z0-9_\-./{}?&=:%+#]+)")
MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret", r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("stripe", r"sk_live_[0-9A-Za-z]{20,}"),
    ("google_api", r"AIza[0-9A-Za-z\-_]{30,}"),
    ("github_token", r"gh[pousr]_[0-9A-Za-z]{20,}"),
    ("slack", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("firebase", r"AIza[0-9A-Za-z\-_]{30,}"),
    ("generic_api", r"(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*[\"']([^\"']{12,})"),
]


@dataclass
class JSReport:
    url: str
    endpoints: list[str] = field(default_factory=list)
    secrets: list[tuple[str, str]] = field(default_factory=list)      # (النوع، القيمة)
    source_maps: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)               # كود مشبوه (eval/atob...)

    @property
    def has_secrets(self) -> bool:
        return bool(self.secrets)


class JSAnalyzer:
    def __init__(self, policy: dict):
        self.policy = policy
        self._cache: dict[str, JSReport] = {}

    # ------------------------------------------------------------------ primitives
    def extract_strings(self, js: str) -> list[str]:
        return [m.group(2) for m in STRING_RE.finditer(js)]

    def extract_endpoints(self, js: str) -> list[str]:
        """نقاط داخل JS: مسارات نسبية أو مطلقة، مع إزالة الأقواس/القالب."""
        out = set()
        for m in ENDPOINT_RE.finditer(js):
            raw = m.group(1)
            if "{" in raw or "}" in raw:
                raw = raw.split("{")[0]
            if len(raw) < 3 or raw.startswith("//"):
                continue
            out.add(raw)
        # أنماط concat('...') و + '...' في بناء المسارات
        for s in self.extract_strings(js):
            if s.startswith(("/api/", "/v1/", "/v2/", "/graphql", "api/")) and " " not in s:
                out.add(s)
        return sorted(out)

    def find_secrets(self, js: str) -> list[tuple[str, str]]:
        out = []
        for kind, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, js):
                val = m.group(1) if m.lastindex else m.group(0)
                if len(val) > 4:
                    out.append((kind, val))
        # إزالة التكرار مع الإبقاء على الترتيب
        seen, uniq = set(), []
        for item in out:
            if item not in seen:
                seen.add(item)
                uniq.append(item)
        return uniq

    def find_source_maps(self, js: str, base_url: str) -> list[str]:
        out = []
        for m in MAP_RE.finditer(js):
            rel = m.group(1)
            out.append(urllib.parse.urljoin(base_url, rel))
        return out

    def suspicious_patterns(self, js: str) -> list[str]:
        hits = []
        checks = [
            (r"eval\s*\(", "eval("),
            (r"atob\s*\(", "atob("),
            (r"document\.write\s*\(", "document.write("),
            (r"innerHTML\s*=", "innerHTML="),
            (r"new\s+Function\s*\(", "new Function("),
            (r"postMessage\s*\(", "postMessage("),
            (r"localStorage\.[gs]etItem\s*\(\s*[\"'](token|session|secret|key)", "localStorage حساس"),
        ]
        for pattern, label in checks:
            if re.search(pattern, js):
                hits.append(label)
        return hits

    # ------------------------------------------------------------------ entry
    async def analyze(self, transport, url: str) -> JSReport | None:
        """جلب وتحليل ملف JS واحد (مع تخزين مؤقت)."""
        if url in self._cache:
            return self._cache[url]
        try:
            r = await transport.get(url)
        except Exception:
            return None
        if r.status != 200:
            return None
        js = r.text
        if not js or len(js) < 32:
            return None
        report = JSReport(
            url=url,
            endpoints=self.extract_endpoints(js),
            secrets=self.find_secrets(js),
            source_maps=self.find_source_maps(js, url),
            suspicious=self.suspicious_patterns(js),
        )
        self._cache[url] = report
        return report

    async def analyze_bundle(self, transport, url: str, depth: int = 1) -> list[JSReport]:
        """تحليل حزمة: يتبع خرائط المصدر حتى العمق المحدد."""
        root = await self.analyze(transport, url)
        if not root:
            return []
        out = [root]
        seen = {url}
        frontier = list(root.source_maps)
        for _ in range(depth):
            nxt = []
            for sm in frontier:
                if sm in seen:
                    continue
                seen.add(sm)
                rep = await self.analyze(transport, sm)
                if rep:
                    out.append(rep)
                    nxt.extend(rep.source_maps)
            frontier = nxt
        return out
