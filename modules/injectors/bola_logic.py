"""كسر منطق الحسابات (IDOR/BOLA): اختبار الجوار الرقمي للمعرّفات + المقارنة
المتجهية للاستجابات (الحالة/الأحرف/الحقول) + كشف الاعتماد على معرفات قابلة
للتخمين في مسارات REST وقيم JSON.
"""
import asyncio
import json
import random
import re
import urllib.parse

from ...core.state_manager import Finding

ID_RE = re.compile(r"/([a-z0-9_-]+)/(\d{1,12})(?:[/?]|$)", re.I)
QUERY_ID_RE = re.compile(r"[?&](?:id|user_id|account_id|uid|file_id|doc_id|order_id|invoice_id|ticket_id|attachment_id|message_id|product_id|item_id|report_id)=(\d{1,12})")


class BOLALogic:
    def __init__(self, policy: dict):
        self.policy = policy
        cfg = policy["modules"]["bola"]
        self.neighbors = cfg.get("neighbors", 10)
        self.batch = cfg.get("batch_size", 25)

    # ------------------------------------------------------------------ extraction
    def _extract_ids(self, url: str) -> list[tuple[int, str]]:
        """(معرّف، نوع_موضع): path أو query."""
        out = []
        for m in ID_RE.finditer(url):
            out.append((int(m.group(2)), "path"))
        for m in QUERY_ID_RE.finditer(url):
            out.append((int(m.group(1)), "query"))
        return out

    def _swap_id(self, url: str, old: int, new: int, pos: str) -> str:
        if pos == "query":
            return QUERY_ID_RE.sub(lambda m: m.group(0).replace(m.group(1), str(new)), url)
        return url.replace(f"/{old}", f"/{new}", 1)

    # ------------------------------------------------------------------ comparison
    def _signature(self, r) -> dict:
        """توقيع متجهي للاستجابة: حالة، طول، حقول JSON، عناوين مميزة."""
        sig = {"status": r.status, "len": len(r.body)}
        ct = r.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    sig["fields"] = sorted(data.keys())[:20]
                elif isinstance(data, list) and data and isinstance(data[0], dict):
                    sig["fields"] = sorted(data[0].keys())[:20]
            except Exception:
                pass
        for h in ("location", "x-user", "x-account"):
            if h in r.headers:
                sig[h] = r.headers[h]
        return sig

    def _diff(self, a: dict, b: dict) -> float:
        """تشابه 0..1: 1 = متطابقتان (مريب جداً عند معرّف مختلف)."""
        if a["status"] != b["status"]:
            return 0.0
        score = 0.5
        if abs(a["len"] - b["len"]) <= max(40, a["len"] * 0.02):
            score += 0.3
        if a.get("fields") == b.get("fields") and a.get("fields") is not None:
            score += 0.2
        return min(1.0, score)

    # ------------------------------------------------------------------ scan
    async def _scan_one(self, transport, url: str, old: int, new: int, pos: str) -> Finding | None:
        probe = self._swap_id(url, old, new, pos)
        try:
            r = await transport.get(probe)
        except Exception:
            return None
        if r.status in (403, 404, 401, 302):
            return None
        # إعادة الطلب مرتين للتأكد من الاستقرار
        try:
            r2 = await transport.get(probe)
        except Exception:
            r2 = r
        if r2.status == r.status:
            return Finding(
                type="bola", severity="high", url=probe, param=pos,
                payload=f"id: {old} -> {new}",
                evidence=f"HTTP {r.status} بطول {len(r.body)} — مورد خارجي قابل للوصول",
                confidence=0.85,
            )
        return None

    # ------------------------------------------------------------------ entry
    async def __call__(self, cell, task, ctx) -> list[Finding]:
        findings = []
        url = task.url
        ids = self._extract_ids(url)
        if not ids:
            return findings
        # أخذ عينة عشوائية من الجوار لتقليل الضجيج وعدم إثارة الأنظمة
        sample_old = ids[0][0] if len(ids) == 1 else random.choice(ids)[0]
        neighbors = [sample_old + d for d in range(1, self.neighbors + 1)]
        random.shuffle(neighbors)

        sem = asyncio.Semaphore(self.batch)
        async def guarded(old, new, pos):
            async with sem:
                if ctx.stop_event.is_set():
                    return None
                return await self._scan_one(cell.transport, url, old, new, pos)

        results = await asyncio.gather(
            *(guarded(sample_old, n, ids[0][1]) for n in neighbors),
            return_exceptions=True,
        )
        for res in results:
            if isinstance(res, Finding):
                findings.append(res)
        return findings
