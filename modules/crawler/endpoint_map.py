"""رسم خريطة الروابط: robots/sitemap + استخراج href + تخمين مسارات شائعة +
استخراج بارامترات، مع تسجيل أولوية (score) لكل نقطة تغذية لمحركات الحقن.
"""
import asyncio
import posixpath
import random
import re
import urllib.parse
from dataclasses import dataclass, field

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,31})=")

COMMON_PATHS = [
    "robots.txt", "sitemap.xml", "admin/", "api/", "api/v1/", "api/v2/", "graphql",
    "swagger", "swagger.json", "api-docs", "openapi.json", ".git/HEAD", ".git/config",
    "config.json", "config.php", ".env", "wp-config.php.bak", "backup.zip", "db.sql",
    "login", "register", "account", "profile", "users", "user", "settings", "admin/login",
    "search", "search?q=test", "download?id=1", "upload", "file?id=1", "doc?id=1",
    "item?id=1", "product?id=1", "order?id=1", "invoice?id=1", "ticket?id=1",
    "message?id=1", "notification?id=1", "attachment?id=1", "avatar?id=1",
    "static/js/", "assets/js/", "webpack/", "vendor/", "node_modules/", "health", "status",
]

EXCLUDE = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".css", ".woff", ".woff2",
           ".svg", ".ico", ".mp4", ".zip", ".pdf"}


@dataclass
class URLRecord:
    url: str
    source: str = "seed"
    depth: int = 0
    params: list[str] = field(default_factory=list)
    score: float = 0.0


class EndpointMapper:
    def __init__(self, policy: dict):
        self.policy = policy
        self.exclude = set(policy["scope"].get("exclude_extensions", EXCLUDE))
        self.max_depth = policy["scope"].get("max_depth", 3)
        self.max_urls = policy["scope"].get("max_urls", 500)

    def _allowed(self, url: str, base_domain: str) -> bool:
        host = urllib.parse.urlparse(url).netloc.lower()
        if not host:
            return False
        domains = self.policy["scope"].get("allowed_domains") or [base_domain]
        return any(host == d or host.endswith("." + d) for d in domains)

    def _skip_ext(self, url: str) -> bool:
        path = urllib.parse.urlparse(url).path.lower()
        return any(path.endswith(e) for e in self.exclude)

    def _score(self, rec: URLRecord) -> float:
        s = 1.0
        if rec.params:
            s += min(len(rec.params), 5) * 1.5
        low = rec.url.lower()
        if any(k in low for k in ("api", "admin", "user", "account", "id=",
                                  "file", "download", "search", "upload", "graphql")):
            s += 2.0
        if rec.depth > 0:
            s -= 0.5 * rec.depth
        return max(0.2, s)

    # ------------------------------------------------------------------ fetchers
    async def _get(self, transport, url: str) -> str | None:
        try:
            r = await transport.get(url)
            if r.status == 200 and "text" in (r.headers.get("content-type", "") or ""):
                return r.text
            if r.status == 200:
                return r.text
        except Exception:
            return None
        return None

    async def robots_and_sitemap(self, transport, base: str) -> list[URLRecord]:
        out: list[URLRecord] = []
        robots = await self._get(transport, base.rstrip("/") + "/robots.txt")
        if robots:
            for m in re.finditer(r"(?im)^(?:Allow|Disallow|Sitemap):\s*(\S+)", robots):
                path = m.group(1)
                if path.startswith("http"):
                    out.append(URLRecord(url=path, source="robots"))
                else:
                    out.append(URLRecord(url=urllib.parse.urljoin(base, path), source="robots"))
        return out

    async def crawl_links(self, transport, url: str, depth: int) -> list[URLRecord]:
        html = await self._get(transport, url)
        if not html:
            return []
        base_domain = urllib.parse.urlparse(url).netloc
        out = []
        for href in HREF_RE.findall(html):
            full = urllib.parse.urljoin(url, href)
            if not self._allowed(full, base_domain) or self._skip_ext(full):
                continue
            params = PARAM_RE.findall(full)
            rec = URLRecord(url=full, source="link", depth=depth, params=params)
            rec.score = self._score(rec)
            out.append(rec)
        return out

    async def fuzz_paths(self, transport, base: str, depth: int) -> list[URLRecord]:
        """تخمين المسارات مع تأخير حسب مستوى التخفي."""
        base = base.rstrip("/")
        out = []
        for path in COMMON_PATHS:
            url = f"{base}/{path}"
            params = PARAM_RE.findall(url)
            rec = URLRecord(url=url, source="fuzz", depth=depth, params=params)
            rec.score = self._score(rec)
            out.append(rec)
        return out

    # ------------------------------------------------------------------ orchestrator entry
    async def map_target(self, transport, base: str) -> list[URLRecord]:
        records: list[URLRecord] = []
        records += await self.robots_and_sitemap(transport, base)
        records += await self.crawl_links(transport, base, 1)
        records += await self.fuzz_paths(transport, base, 1)

        seen: set[str] = set()
        final: list[URLRecord] = []
        for rec in sorted(records, key=lambda r: -r.score):
            if rec.url in seen:
                continue
            seen.add(rec.url)
            final.append(rec)
            if len(final) >= self.max_urls:
                break
        return final
