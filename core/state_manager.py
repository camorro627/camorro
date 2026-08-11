"""حالة الهجوم: SQLite غير متزامن + تشفير الحقول الحساسة + نقاط استعادة.

الجداول:
  cells    — حالة كل خلية (بروكسي، بصمة، عدادات).
  findings — النتائج (الحمولة/الدليل مشفران).
  tasks    — سجل المهام المنفذة.
  meta     — نقاط الاستعادة (checkpoint) كمفاتيح JSON.
"""
import asyncio
import json
import time
import uuid
from dataclasses import asdict, dataclass, field

import aiosqlite

from .crypto_vault import CryptoVault


@dataclass
class Finding:
    type: str                       # sql | xss | bola | endpoint | js_secret | waf
    severity: str                   # critical | high | medium | low | info
    url: str
    param: str | None = None
    payload: str | None = None
    evidence: str = ""
    confidence: float = 1.0
    cell_id: str = ""
    meta: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    @property
    def id(self) -> str:
        return uuid.uuid4().hex[:12]


class AttackState:
    def __init__(self, db_path: str = "./swarm_state.db", vault: CryptoVault | None = None):
        self.db_path = db_path
        self.vault = vault
        self._db: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------ lifecycle
    async def init(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS cells (
                id TEXT PRIMARY KEY,
                profile TEXT, proxy TEXT, status TEXT,
                requests INTEGER DEFAULT 0, failures INTEGER DEFAULT 0,
                findings INTEGER DEFAULT 0, last_activity REAL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, type TEXT, severity TEXT, url TEXT,
                param TEXT, payload_enc BLOB, evidence_enc BLOB,
                confidence REAL, cell_id TEXT, meta_enc BLOB, ts REAL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, kind TEXT, url TEXT, cell_id TEXT,
                status TEXT, ts REAL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value BLOB, ts REAL
            );
            """
        )
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    # ------------------------------------------------------------------ cells
    async def add_cell(self, cell_id: str, profile: str, proxy: str) -> None:
        await self._db.execute(
            "INSERT OR REPLACE INTO cells (id, profile, proxy, status, last_activity) VALUES (?,?,?,?,?)",
            (cell_id, profile, proxy, "idle", time.time()),
        )
        await self._db.commit()

    async def update_cell(self, cell_id: str, **kw) -> None:
        cols = ", ".join(f"{k}=?" for k in kw)
        await self._db.execute(f"UPDATE cells SET {cols} WHERE id=?", (*kw.values(), cell_id))
        await self._db.commit()

    # ------------------------------------------------------------------ findings
    async def add_finding(self, f: Finding) -> None:
        enc = lambda s: self.vault.seal(s.encode()) if self.vault else s.encode()
        await self._db.execute(
            "INSERT INTO findings (id, type, severity, url, param, payload_enc, evidence_enc, confidence, cell_id, meta_enc, ts) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                f.id, f.type, f.severity, f.url, f.param,
                enc(f.payload or ""), enc(f.evidence), f.confidence, f.cell_id,
                enc(json.dumps(f.meta)), f.ts,
            ),
        )
        await self._db.commit()

    async def count_findings(self, ftype: str | None = None) -> int:
        if ftype:
            cur = await self._db.execute("SELECT COUNT(*) FROM findings WHERE type=?", (ftype,))
        else:
            cur = await self._db.execute("SELECT COUNT(*) FROM findings")
        row = await cur.fetchone()
        return int(row[0])

    # ------------------------------------------------------------------ checkpoints
    async def checkpoint(self, key: str, data: dict) -> None:
        blob = self.vault.seal(json.dumps(data).encode()) if self.vault else json.dumps(data).encode()
        await self._db.execute(
            "INSERT OR REPLACE INTO meta (key, value, ts) VALUES (?,?,?)", (key, blob, time.time())
        )
        await self._db.commit()

    # ------------------------------------------------------------------ snapshot
    async def snapshot(self) -> dict:
        """لقطة للوحة التحكم."""
        cells = []
        async with self._db.execute("SELECT id, profile, proxy, status, requests, failures, findings, last_activity FROM cells") as cur:
            async for row in cur:
                cells.append(
                    {"id": row[0], "profile": row[1], "proxy": row[2], "status": row[3],
                     "requests": row[4], "failures": row[5], "findings": row[6], "last_activity": row[7]}
                )
        recent = []
        async with self._db.execute("SELECT type, severity, url, param, ts FROM findings ORDER BY ts DESC LIMIT 12") as cur:
            async for row in cur:
                recent.append({"type": row[0], "severity": row[1], "url": row[2], "param": row[3], "ts": row[4]})
        return {
            "cells": cells,
            "findings_total": await self.count_findings(),
            "findings_recent": recent,
            "ts": time.time(),
        }
