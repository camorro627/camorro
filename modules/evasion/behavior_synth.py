"""تخليق سلوك بشري عشوائي: توقيتات لوج-نرمالية، مسارات تصفح ماركوفية،
حركة مؤشر منحنية (Bezier)، ملفات كتابة، وانجراف زمني حسب المنطقة الزمنية للشخصية.
"""
import math
import random
import time
import zoneinfo
from dataclasses import dataclass, field


@dataclass
class Persona:
    name: str
    os: str
    tz: str
    locale: str
    work_start: int = 9
    work_end: int = 19
    scroll_style: str = "smooth"          # smooth | jittery | fast
    typing_wpm: float = random.uniform(38, 65)


class BehaviorEngine:
    def __init__(self, policy: dict, persona_seed: int | None = None):
        self.rng = random.Random(persona_seed)
        self.policy = policy
        self.persona = Persona(
            name=self.rng.choice(["emma", "liam", "noah", "mia", "sofia", "omar"]),
            os=self.rng.choice(["Windows", "macOS", "Linux"]),
            tz=self.rng.choice(["America/New_York", "Europe/London", "Asia/Dubai",
                                "Asia/Riyadh", "Europe/Berlin", "Asia/Tokyo"]),
            locale=self.rng.choice(["en-US", "en-GB", "ar-SA", "de-DE", "fr-FR"]),
            typing_wpm=self.rng.uniform(38, 65),
        )

    # ------------------------------------------------------------ timing
    async def think(self) -> float:
        """توقيت تفكير لوج-نرمالي (ذيل طويل: أحياناً توقف طويل كإنسان حقيقي)."""
        s = self.policy["stealth"]
        mu, sigma = 1.2, 0.9
        delay = math.exp(self.rng.gauss(mu, sigma))
        delay = min(max(delay, 0.3), 18.0)
        await asyncio_sleep(delay * self._activity_factor())
        return delay

    def _activity_factor(self) -> float:
        """انجراف سلوكي حسب ساعة اليوم في منطقة الشخصية."""
        try:
            hour = time.localtime().tm_hour
        except Exception:
            hour = 12
        if self.persona.work_start <= hour <= self.persona.work_end:
            return 0.55        # نشيط: أسرع
        return 1.0             # خارج الدوام: أبطأ وأكثر تردداً

    async def before_request(self) -> None:
        """يُستدعى قبل كل طلب حرج."""
        await self.think()

    # ------------------------------------------------------------ navigation
    def navigation_path(self, links: list[str], max_steps: int = 6) -> list[str]:
        """سير ماركوفي: انتقالات واقعية مع احتمال العودة للصفحات السابقة."""
        if not links:
            return []
        path, seen = [], set()
        for _ in range(max_steps):
            if self.rng.random() < 0.2 and path:        # زر الرجوع
                path.append(self.rng.choice(path))
                continue
            candidates = [l for l in links if l not in seen]
            if not candidates:
                break
            nxt = self.rng.choice(candidates)
            path.append(nxt)
            seen.add(nxt)
        return path

    # ------------------------------------------------------------ input synthesis
    def typing_delays(self, text: str) -> list[float]:
        """فترات ضغط مفاتيح بوحدة المللي ثانية حسب WPM + تردد بطيء عند الرموز."""
        base = 60000.0 / (self.persona.typing_wpm * 5.0)
        out = []
        for ch in text:
            d = base * self.rng.uniform(0.75, 1.35)
            if ch in "!@#$%^&*()_+-=[]{};':\",./<>?\\|`~":
                d *= self.rng.uniform(1.8, 3.0)         # رموز صعبة
            out.append(d)
        return out

    def mouse_path(self, x0: float, y0: float, x1: float, y1: float,
                   steps: int = 24) -> list[tuple[float, float]]:
        """منحنى Bezier تكعيبي مع انحناء عشوائي — لا خطوط مستقيمة آلائية."""
        cx = (x0 + x1) / 2 + self.rng.uniform(-80, 80)
        cy = (y0 + y1) / 2 + self.rng.uniform(-60, 60)
        pts = []
        for i in range(steps + 1):
            t = i / steps
            mt = 1 - t
            x = mt**3 * x0 + 3 * mt**2 * t * cx + 3 * mt * t**2 * cx + t**3 * x1
            y = mt**3 * y0 + 3 * mt**2 * t * cy + 3 * mt * t**2 * cy + t**3 * y1
            pts.append((x, y))
        return pts

    def scroll_curve(self, viewport_h: int, content_h: int,
                     steps: int = 40) -> list[tuple[float, float]]:
        """منحنى تمرير ease-in-out مع توقفات وقراءات قصيرة."""
        max_y = max(0, content_h - viewport_h)
        curve = []
        for i in range(steps + 1):
            t = i / steps
            eased = t * t * (3 - 2 * t)                 # smoothstep
            y = eased * max_y
            curve.append((time.monotonic(), y))
            if self.rng.random() < 0.12:                # توقف للقراءة
                curve.append((time.monotonic() + self.rng.uniform(0.6, 2.4), y))
        return curve

    # ------------------------------------------------------------ session drift
    def drift_headers(self, headers: dict) -> dict:
        """تعديل رؤوس بشكل بطيء مع الزمن: إعادة ترتيب Accept، تغيير اللغة أحياناً."""
        h = dict(headers)
        if self.rng.random() < 0.1:
            h["accept-language"] = self.persona.locale + ",en;q=0.7"
        if self.rng.random() < 0.05:
            h.pop("sec-ch-ua-platform", None)
        return h


def asyncio_sleep(delay: float):
    import asyncio
    return asyncio.sleep(delay)
