"""لوحة تحكم حية: شريط حالة علوي (خلايا/نتائج/بروكسيات) + جدول النتائج +
مخطط شريطي للأنواع. تُحدَّث عبر حلقة خلفية؛ تعمل حتى بدون TTY (تسقط بصمت)."""
import asyncio
import threading
import time

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH = True
except ImportError:
    RICH = False

SEV_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "blue"}
TYPE_LABEL = {"sql": "SQLi", "xss": "XSS", "bola": "IDOR", "endpoint": "نقطة", "js_secret": "سر JS", "waf": "WAF"}


class Dashboard:
    def __init__(self, state, mesh, enabled: bool = True):
        self.state = state
        self.mesh = mesh
        self.enabled = enabled and RICH
        self._findings: list[dict] = []
        self._lock = threading.Lock()
        self._console = Console() if self.enabled else None

    # ------------------------------------------------------------------ push (من الخلايا)
    def push(self, finding) -> None:
        with self._lock:
            self._findings.append({
                "type": finding.type, "severity": finding.severity,
                "url": finding.url, "param": finding.param or "",
                "ts": time.time(),
            })
            self._findings = self._findings[-200:]

    # ------------------------------------------------------------------ render
    def _snapshot(self) -> dict:
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            snap = loop.run_until_complete(self.state.snapshot())
            loop.close()
            return snap
        except Exception:
            return {"cells": [], "findings_total": 0, "findings_recent": []}

    def _render(self) -> Panel:
        snap = self._snapshot()
        cells = snap.get("cells", [])
        alive = sum(1 for c in cells if c["status"] != "dead")
        total_req = sum(c["requests"] for c in cells)
        mesh_s = self.mesh.stats()

        status = Table.grid(expand=True)
        status.add_column(justify="left")
        status.add_column(justify="right")
        status.add_row(
            Text(f"SwarmAttack Framework", style="bold cyan"),
            Text(f"{time.strftime('%H:%M:%S')}", style="dim"),
        )
        status.add_row(
            Text(f"خلايا: {alive}/{len(cells)} | طلبات: {total_req} | نتائج: {snap['findings_total']}"),
            Text(f"بروكسيات: {mesh_s['healthy']}/{mesh_s['total']} صحي (محظور {mesh_s['banned']})"),
        )

        table = Table(title="النتائج الأخيرة", header_style="bold")
        table.add_column("النوع", width=7)
        table.add_column("الخطورة", width=9)
        table.add_column("URL", width=60, overflow="fold")
        table.add_column("البارامتر", width=18, overflow="fold")
        with self._lock:
            recent = list(reversed(self._findings[-12:]))
        for f in recent:
            table.add_row(
                TYPE_LABEL.get(f["type"], f["type"]),
                Text(f["severity"], style=SEV_COLORS.get(f["severity"], "white")),
                f["url"], f["param"],
            )
        if not recent:
            table.add_row("—", "—", "بانتظار النتائج…", "—")

        return Panel(
            status, title="[bold green]SwarmAttack — Live Dashboard[/]",
            border_style="green", padding=(1, 2),
        )  # + جدول منفصل داخل نفس اللوحة

    # ------------------------------------------------------------------ run
    async def run(self, stop: asyncio.Event) -> None:
        if not self.enabled:
            while not stop.is_set():
                await asyncio.sleep(5)
            return
        with Live(self._render(), console=self._console, refresh_per_second=2) as live:
            while not stop.is_set():
                live.update(self._render())
                await asyncio.sleep(1.0)
