"""زاحف endpoints + محلل JS ضد وكلاء وهمية."""
from types import SimpleNamespace

import pytest

from modules.crawler.endpoint_map import EndpointMapper
from modules.crawler.js_analyzer import JSAnalyzer
from conftest import FakeCell, FakeResponse


def test_robots_sitemap_parsing(policy):
    routes = {
        "http://site/robots.txt": FakeResponse(
            200, "User-agent: *\nDisallow: /admin\nSitemap: http://site/sitemap.xml"),
        "http://site/": FakeResponse(200, "<a href='/products?id=1'>p</a>"),
    }
    cell = FakeCell(routes)
    mapper = EndpointMapper(policy)

    async def run():
        recs = await mapper.robots_and_sitemap(cell.transport, "http://site")
        links = await mapper.crawl_links(cell.transport, "http://site", 1)
        return recs, links

    recs, links = asyncio_run(run())
    urls = [r.url for r in recs] + [l.url for l in links]
    assert "http://site/sitemap.xml" in urls
    assert any("/products?id=1" in u for u in urls)
    assert any("/admin" in u for u in urls)          # Disallow يُجمَّع كنقطة


def test_endpoint_score_prioritizes_params(policy):
    from modules.crawler.endpoint_map import URLRecord
    mapper = EndpointMapper(policy)
    r1 = URLRecord(url="http://s/api?user_id=1&token=x", params=["user_id", "token"])
    r2 = URLRecord(url="http://s/static.html", params=[])
    assert mapper._score(r1) > mapper._score(r2)


def test_js_analyzer_finds_endpoints_secrets(policy):
    js = """
    const API = "/api/v1/users/" + id;
    fetch('https://api.example.com/v2/reports?format=json');
    const key = "AKIAIOSFODNN7EXAMPLE";
    //# sourceMappingURL=/static/app.js.map
    eval(atob("aGk="));
    """
    from modules.crawler.js_analyzer import JSAnalyzer
    a = JSAnalyzer(policy)
    eps = a.extract_endpoints(js)
    assert "/api/v1/users/" in eps or "/api/v1/users/" in str(eps)
    secrets = a.find_secrets(js)
    assert any(k == "aws_access_key" for k, v in secrets)
    assert a.find_source_maps(js, "http://s/app.js") == ["http://s/static/app.js.map"]
    assert "eval(" in a.suspicious_patterns(js)


def test_js_analyzer_fetch(policy):
    routes = {
        "http://s/app.js": FakeResponse(200,
            "fetch('/api/admin'); var token='ghp_ABCDEF1234567890';",
            headers={"content-type": "application/javascript"}),
    }
    cell = FakeCell(routes)
    a = JSAnalyzer(policy)

    async def run():
        return await a.analyze(cell.transport, "http://s/app.js")

    rep = asyncio_run(run())
    assert rep is not None
    assert "/api/admin" in rep.endpoints
    assert any(k == "github_token" for k, v in rep.secrets)


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
