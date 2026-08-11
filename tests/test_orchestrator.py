"""اختبار التكامل: 3 خلايا + محرك SQL وهمي → نتائج في قاعدة الحالة."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import AttackState, CryptoVault, Orchestrator, Task  # noqa: E402
from core.state_manager import Finding  # noqa: E402
from modules.evasion.proxy_mesh import ProxyMesh  # noqa: E402
from conftest import MINI_POLICY  # noqa: E402


class FakeSQL:
    """محرك وهمي: كل مهمة تعيد نتيجة SQL ثابتة بعد محاكاة عمل."""
    async def __call__(self, cell, task, ctx):
        await asyncio.sleep(0.01)
        return [Finding(type="sql", severity="high", url=task.url,
                        param=task.param or "id", payload="'",
                        evidence="fake-detector", confidence=0.9)]


@pytest.mark.asyncio
async def test_orchestrator_full_flow(tmp_path):
    import copy
    policy = copy.deepcopy(MINI_POLICY)
    policy["stealth"]["max_cells"] = 3

    vault = CryptoVault(b"orchestrator-test-key-0000000000000000")
    state = AttackState(str(tmp_path / "or.db"), vault=vault)
    await state.init()

    mesh = ProxyMesh([], policy)                    # بدون بروكسيات خارجية
    orch = Orchestrator(policy, [PROFILE_DICT], mesh, vault, state)
    orch.register_modules({"sql": FakeSQL()})

    await orch.submit(Task(kind="sql", url="http://t/?id=1", param="id"))
    await orch.submit(Task(kind="sql", url="http://t/?user=2", param="user"))
    await orch.submit(Task(kind="sql", url="http://t/?file=3", param="file"))

    # تشغيل مباشر للعمال (بدون حلقة الزحف)
    stop = asyncio.Event()
    workers = [asyncio.create_task(orch._worker(c)) for c in orch.cells]
    await asyncio.sleep(0.5)
    stop.set()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    assert await state.count_findings("sql") >= 3
    snap = await state.snapshot()
    assert snap["findings_total"] >= 3
    await state.close()
