"""شبكة بروكسي دوّارة مع دوائر لزجة (sticky circuits) وفحص صحي وعدّادات موثوقية.

- كل خلية تلتصق ببروكسي واحد حتى حد الاستخدام أو فشل متكرر، ثم تُدار.
- الفشل يُسجَّل ويُفرض "عقوبة" مؤقتة على البروكسي (حتى لا يعيد التوزيع إليه).
- النقل الفعلي عبر curl_cffi مع تقليد البصمة (impersonation) — لا يمكن ربط
  الطلب بالبصمة الأصلية للمكتبة.
"""
import asyncio
import random
import time
from dataclasses import dataclass, field

from curl_cffi.requests import AsyncSession


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    url: str
    elapsed: float

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class ProxyRecord:
    url: str
    kind: str = "http"                    # http | socks4 | socks5
    uses: int = 0
    failures: int = 0
    healthy: bool = True
    latency: float = 0.0
    banned_until: float = 0.0
    country: str = ""


class ProxyMesh:
    def __init__(self, proxy_urls: list[str], policy: dict):
        self.policy = policy
        self.records: list[ProxyRecord] = []
        for u in proxy_urls:
            u = u.strip()
            if not u:
                continue
            kind = "socks5" if u.startswith("socks5") else "socks4" if u.startswith("socks4") else "http"
            self.records.append(ProxyRecord(url=u, kind=kind))

    @classmethod
    def from_file(cls, path: str | None, policy: dict) -> "ProxyMesh":
        if not path:
            return cls([], policy)
        with open(path, "r", encoding="utf-8") as fh:
            return cls([l for l in fh.read().splitlines() if l.strip()], policy)

    # ------------------------------------------------------------------ health
    async def health_check_all(self) -> None:
        """فحص متزامن عبر aiohttp: بروكسي ميت = healthy=False."""
        import aiohttp

        async def _check(rec: ProxyRecord):
            t0 = time.monotonic()
            try:
                proxy = f"http://{rec.url}" if rec.kind == "http" and not rec.url.startswith("http") else rec.url
                timeout = aiohttp.ClientTimeout(total=self.policy["network"]["health_timeout"])
                async with aiohttp.ClientSession(timeout=timeout) as s:
                    async with s.get("https://www.gstatic.com/generate_204",
                                     proxy=proxy, ssl=False) as r:
                        rec.latency = time.monotonic() - t0
                        rec.healthy = r.status in (200, 204)
            except Exception:
                rec.healthy = False

        await asyncio.gather(*(_check(r) for r in self.records))

    # ------------------------------------------------------------------ acquire / release
    def acquire(self) -> dict:
        now = time.monotonic()
        pool = [r for r in self.records
                if r.healthy and r.banned_until < now
                and r.uses < self.policy["network"]["max_proxy_uses"]]
        if not pool:
            pool = [r for r in self.records if r.banned_until < now]
        if not pool:
            raise RuntimeError("لا يوجد بروكسي متاح في الشبكة")
        rec = random.choice(pool)
        rec.uses += 1
        return {"url": rec.url, "kind": rec.kind}

    def release(self, proxy_url: str, ok: bool) -> None:
        for r in self.records:
            if r.url == proxy_url:
                if ok:
                    r.failures = max(0, r.failures - 1)
                else:
                    r.failures += 1
                    if r.failures >= 3:
                        r.banned_until = time.monotonic() + 60 * (2 ** min(r.failures, 5))
                        r.healthy = False
                return

    def rotate(self, cell) -> str:
        """إعادة تدوير بروكسي خلية — تُسمى من الدائرة الكهربائية في المنسق."""
        old = cell.transport.proxy_url
        self.release(old, ok=False)
        new = self.acquire()
        cell.transport.proxy_url = new["url"]
        return new["url"]

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict:
        return {
            "total": len(self.records),
            "healthy": sum(1 for r in self.records if r.healthy),
            "banned": sum(1 for r in self.records if r.banned_until > time.monotonic()),
        }


class CellTransport:
    """ناقل خلية: جلسة curl_cffi ثابتة مع بصمة + بروكسي + سياسة استرجاع."""

    def __init__(self, proxy_url: str, impersonation: str,
                 extra_headers: dict, policy: dict, mesh: ProxyMesh, cell_id: str):
        self.proxy_url = proxy_url
        self.impersonation = impersonation
        self.extra_headers = extra_headers
        self.policy = policy
        self.mesh = mesh
        self.cell_id = cell_id
        self._session: AsyncSession | None = None

    async def _get_session(self) -> AsyncSession:
        if self._session is None:
            self._session = AsyncSession(
                impersonate=self.impersonation,
                proxies={"http": self.proxy_url, "https": self.proxy_url},
                verify=False,
                timeout=30,
                headers=dict(self.extra_headers),
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def request(self, method: str, url: str, **kw) -> Response:
        """طلب واحد مع استرجاع تصاعدي (1,2,4) عبر بروكسيات بديلة."""
        s = self.policy["stealth"]
        attempts = kw.pop("_retries", 2)
        for attempt in range(attempts + 1):
            t0 = time.monotonic()
            try:
                session = await self._get_session()
                r = await session.request(method, url, **kw)
                resp = Response(
                    status=r.status_code,
                    headers=dict(r.headers),
                    body=r.content,
                    url=str(r.url),
                    elapsed=time.monotonic() - t0,
                )
                self.mesh.release(self.proxy_url, ok=resp.status < 500)
                return resp
            except Exception:
                self.mesh.release(self.proxy_url, ok=False)
                if attempt < attempts:
                    self.proxy_url = self.mesh.acquire()["url"]
                    await self.close()
                    await asyncio.sleep(random.uniform(*s["cooldown_after_rotate"]))
                else:
                    raise
        raise RuntimeError("استُنفدت محاولات النقل")  # pragma: no cover

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)
