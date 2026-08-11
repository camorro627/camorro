"""محركات الحقن ضد وكلاء وهمية تحاكي تطبيقاً هشّاً."""
import pytest

from core.state_manager import Finding
from modules.injectors.bola_logic import BOLALogic
from modules.injectors.sql_swarm import SQLSwarm
from modules.injectors.xss_swarm import XSSSwarm

from conftest import FakeCell, FakeResponse


@pytest.mark.asyncio
async def test_sql_error_based(policy):
    routes = {
        "http://vuln/?id=": FakeResponse(200, "You have an error in your SQL syntax"),
    }
    cell = FakeCell(routes)
    sql = SQLSwarm(policy)
    findings = await sql(cell, None, SimpleCtx(policy))
    assert any(f.type == "sql" for f in findings)
    assert findings[0].confidence > 0.9


@pytest.mark.asyncio
async def test_sql_time_based(policy):
    import time
    t0 = time.monotonic()

    class SlowTransport:
        async def get(self, url, **kw):
            if "SLEEP" in url or "pg_sleep" in url:
                time.sleep(1.6)            # استجابة بطيئة للحمولة الزمنية
            return FakeResponse(200, "ok")
        async def post(self, url, **kw):
            return FakeResponse(200, "{}")

    cell = FakeCell({})
    cell.transport = SlowTransport()
    sql = SQLSwarm(policy)
    policy["modules"]["sql"]["time_delay"] = 2
    policy["modules"]["sql"]["tests"] = ["time"]
    findings = await sql(cell, None, SimpleCtx(policy))
    assert any(f.type == "sql" and f.severity == "critical" for f in findings)


@pytest.mark.asyncio
async def test_sql_waf_detected(policy):
    routes = {"http://vuln/?id=": FakeResponse(403, "Request blocked by Cloudflare")}
    sql = SQLSwarm(policy)
    policy["modules"]["sql"]["tests"] = ["error"]
    findings = await sql(FakeCell(routes), None, SimpleCtx(policy))
    assert any(f.type == "waf" for f in findings)


@pytest.mark.asyncio
async def test_xss_reflected(policy):
    payload_marker = "alert(1)"
    routes = {}
    def make(url):
        return FakeResponse(200, f"<html>search: {url.split('q=')[-1]}</html>")
    cell = FakeCell({})
    # انعكاس مباشر مهما كانت قيمة q
    class EchoTransport:
        async def get(self, url, **kw):
            val = url.split("q=")[-1]
            return FakeResponse(200, f"<div>result for {val}</div>")
        async def post(self, url, **kw):
            return FakeResponse(200, "{}")
    cell.transport = EchoTransport()
    xss = XSSSwarm(policy)
    from types import SimpleNamespace
    task = SimpleNamespace(url="http://vuln/search?q=1", extra={"params": ["q"]})
    findings = await xss(cell, task, SimpleCtx(policy))
    assert any(f.type == "xss" for f in findings)


@pytest.mark.asyncio
async def test_bola_neighbor_access(policy):
    routes = {}
    class OpenTransport:
        async def get(self, url, **kw):
            # كل المعرفات مفتوحة عدا 403/404
            if "/users/9999" in url:
                return FakeResponse(404, "nf")
            if "id=" in url and "1000" in url:
                return FakeResponse(403, "denied")
            return FakeResponse(200, '{"name": "victim", "email": "x@y.z"}')
        async def post(self, url, **kw):
            return FakeResponse(200, "{}")
    cell = FakeCell({})
    cell.transport = OpenTransport()
    bola = BOLALogic(policy)
    from types import SimpleNamespace
    task = SimpleNamespace(url="http://api/users/1001", extra={})
    findings = await bola(cell, task, SimpleCtx(policy))
    assert any(f.type == "bola" for f in findings)


class SimpleCtx:
    """سياق وهمي مصغّر يكفي للمحركات."""
    def __init__(self, policy):
        self.policy = policy
        self.stop_event = _NeverStop()


class _NeverStop:
    def is_set(self):
        return False
