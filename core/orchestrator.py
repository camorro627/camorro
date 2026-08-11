#!/usr/bin/env python3
"""المنسق العام (Orchestrator): بناء الخلايا، توزيع المهام، الدوائر الكهربائية، التوسع الديناميكي.

كل خلية = بروكسي + بصمة TLS + محرك سلوك بشري، وتعمل كمستهلك مستقل من طابور
المهام — هكذا يُنفَّذ "الهجوم العنقودي" دون أن يصدر تدفق الطلبات من نقطة واحدة.
"""
import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field

# استيراد مطلق آمن متوافق مع جذر المشروع المهيأ في swarm.py
from core.state_manager import AttackState, Finding
from modules.evasion.behavior_synth import BehaviorEngine
from modules.evasion.ja4_mutator import FingerprintBank, impersonate_for
from modules.evasion.proxy_mesh import CellTransport, ProxyMesh


@dataclass
class Cell:
    id: str
    profile: dict
    transport: "CellTransport"
    behavior: "BehaviorEngine"
    status: str = "idle"          # idle | busy | cooldown | dead
    requests: int = 0
    failures: int = 0
    findings: int = 0
    last_activity: float = 0.0


@dataclass
class Task:
    kind: str                     # crawl | js | sql | xss | bola
    url: str
    param: str | None = None
    depth: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return uuid.uuid4().hex[:10]


@dataclass
class AttackContext:
    policy: dict
    mesh: "ProxyMesh"
    vault: object
    state: "AttackState"
    logger: object | None = None
    dashboard_push: callable = lambda f: None
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)


class Orchestrator:
    def __init__(self, policy: dict, profiles: list[dict], mesh: ProxyMesh,
                 vault, state: AttackState, logger=None, dashboard=None):
        self.policy = policy
        self.mesh = mesh
        self.vault = vault
        self.state = state
        self.logger = logger
        self.dashboard = dashboard
        self.bank = FingerprintBank(profiles)
        self.module_handlers: dict[str, callable] = {}
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=4096)
        self._cells: list[Cell] = []
        self._stop = asyncio.Event()
        self._tasks_done = 0
        self._tokens: dict[str, float] = {}
        self._last_token_refill: dict[str, float] = {}

    # ------------------------------------------------------------------ setup
    def register_modules(self, handlers: dict[str, callable]) -> None:
        self.module_handlers.update(handlers)

    def _build_cell(self, idx: int) -> Cell:
        profile = self.bank.mutated_profile()          # بصمة TLS مطفَّرة
        proxy = self.mesh.acquire()
        impersonate = impersonate_for(profile)
        
        cell = Cell(
            id=f"cell-{idx:02d}",
            profile=profile,
            transport=CellTransport(
                proxy_url=proxy["url"] if proxy else None,
                impersonation=impersonate,
                extra_headers=profile.get("headers", {}),
                policy=self.policy,
                mesh=self.mesh,
                cell_id=f"cell-{idx:02d}",
            ),
            behavior=BehaviorEngine(self.policy, persona_seed=random.randrange(1 << 30)),
        )
        self._tokens[cell.id] = float(self.policy["stealth"].get("max_rpm", 60))
        self._last_token_refill[cell.id] = time.monotonic()
        return cell

    # ------------------------------------------------------------------ rate limiting
    async def _rate_limit(self, cell: Cell) -> None:
        """مقياس رمزي (token bucket) لكل خلية على حدة."""
        s = self.policy["stealth"]
        now = time.monotonic()
        rate = s.get("max_rpm", 60) / 60.0
        
        self._tokens[cell.id] = min(
            rate, self._tokens[cell.id] + (now - self._last_token_refill[cell.id]) * rate
        )
        self._last_token_refill[cell.id] = now
        
        if self._tokens[cell.id] < 1.0:
            wait = (1.0 - self._tokens[cell.id]) / rate
            await asyncio.sleep(wait)
            self._tokens[cell.id] = 0.0
        else:
            self._tokens[cell.id] -= 1.0

    async def _humanize(self, cell: Cell) -> None:
        s = self.policy["stealth"]
        d0, d1 = s["delay_range"]
        delay = random.uniform(d0, d1) * (1 + random.uniform(-s["jitter"], s["jitter"]))
        await asyncio.sleep(max(0.05, delay))
        
        if self.policy["behavior"].get("humanize", True) and random.random() < 0.18:
            t0, t1 = s["think_time_range"]
            await asyncio.sleep(random.uniform(t0, t1) * 0.35)

    # ------------------------------------------------------------------ healing
    async def _heal(self, cell: Cell) -> None:
        cell.status = "cooldown"
        cell.failures = 0
        self.mesh.rotate(cell)
        await asyncio.sleep(random.uniform(*self.policy["stealth"]["cooldown_after_rotate"]))
        cell.status = "idle"

    # ------------------------------------------------------------------ workers
    async def _worker(self, cell: Cell) -> None:
        while not self._stop.is_set():
            task = await self._queue.get()
            if task is None:
                self._queue.task_done()
                break
            cell.status = "busy"
            try:
                await self._rate_limit(cell)
                await self._humanize(cell)
                
                handler = self.module_handlers.get(task.kind)
                findings: list[Finding] = []
                if handler is not None:
                    findings = await handler(cell, task, AttackContext(
                        policy=self.policy, 
                        mesh=self.mesh, 
                        vault=self.vault,
                        state=self.state, 
                        logger=self.logger,
                        dashboard_push=self.dashboard.push if self.dashboard else (lambda f: None),
                        stop_event=self._stop,
                    ))
                    
                for f in findings:
                    f.cell_id = cell.id
                    await self.state.add_finding(f)
                    cell.findings += 1
                    if self.dashboard:
                        self.dashboard.push(f)
                cell.requests += 1
                self._tasks_done += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — شبكة: بروكسي ميت، مهلة، إلخ
                cell.failures += 1
                if self.logger:
                    self.logger.error(f"Cell execution error: {exc}", cell_id=cell.id)
                if cell.failures >= self.policy["stealth"]["circuit_breaker"]:
                    await self._heal(cell)
            finally:
                cell.status = "idle"
                cell.last_activity = time.time()
                await self.state.update_cell(
                    cell.id, status=cell.status, requests=cell.requests,
                    failures=cell.failures, findings=cell.findings,
                    last_activity=cell.last_activity,
                )
                self._queue.task_done()

    # ------------------------------------------------------------------ run
    async def run(self, targets: list[str]) -> None:
        n = min(self.policy["stealth"]["max_cells"], 24)
        for i in range(n):
            cell = self._build_cell(i)
            self._cells.append(cell)
            await self.state.add_cell(cell.id, cell.profile.get("name", "?"), cell.transport.proxy_url)

        for t in targets:
            await self._queue.put(Task(kind="crawl", url=t, depth=0))

        workers = [asyncio.create_task(self._worker(c)) for c in self._cells]
        watchdog = asyncio.create_task(self._watchdog())
        
        await self._queue.join()
        self._stop.set()
        
        for w in workers:
            w.cancel()
        watchdog.cancel()
        
        await asyncio.gather(*workers, watchdog, return_exceptions=True)

    async def _watchdog(self) -> None:
        """مراقب صحة: يمد الخلايا الميتة والراكدة بالدعم التلقائي والتدوير."""
        while not self._stop.is_set():
            await asyncio.sleep(15)
            for cell in self._cells:
                if cell.status == "dead" or (cell.status == "idle" and time.time() - cell.last_activity > 120):
                    cell.status = "cooldown"
                    self.mesh.rotate(cell)
                    cell.failures = 0
                    cell.status = "idle"

    async def submit(self, task: Task) -> None:
        if self._queue.qsize() < self._queue.maxsize:
            await self._queue.put(task)

    @property
    def cells(self) -> list[Cell]:
        return self._cells
