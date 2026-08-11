"""إعداد مشترك: بيانات اصطناعية، سياسة مصغّرة، ووكلاء وهمية."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.crypto_vault import CryptoVault  # noqa: E402
from core.state_manager import AttackState, Finding  # noqa: E402
from modules.evasion.ja4_mutator import TLSProfile  # noqa: E402

MINI_POLICY = {
    "stealth": {"max_cells": 3, "delay_range": [0.0, 0.05], "jitter": 0.1,
                "think_time_range": [0.0, 0.1], "max_rpm": 600,
                "circuit_breaker": 3, "cooldown_after_rotate": [0.0, 0.1]},
    "behavior": {"humanize": False},
    "scope": {"allowed_domains": [], "max_depth": 2, "max_urls": 100,
              "exclude_extensions": [".png", ".jpg", ".css"]},
    "modules": {"enabled": ["sql", "xss", "bola"],
                "sql": {"tests": ["error", "boolean"], "time_delay": 2,
                        "max_params_per_url": 10},
                "xss": {"dom_check": False, "polyglot": True},
                "bola": {"neighbors": 5, "batch_size": 10}},
    "network": {"proxy_file": None, "health_timeout": 3, "max_proxy_uses": 50},
    "crypto": {"key_env_var": "SWARM_TEST_KEY"},
    "reporting": {"export_dir": "/tmp/swarm_tests"},
}

PROFILE_DICT = {
    "name": "test_chrome", "family": "chrome",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "platform": "Windows", "tls_version": "13",
    "ciphers": [1301, 1302, 1303, 49195, 49199, 49196, 49200, 52393, 52392,
                49171, 49172, 156, 157, 47, 53],
    "extensions": [17513, 27, 23, 16, 13, 51, 45, 5, 0, 10, 18, 21, 15, 11, 65299],
    "sigalgs": [2570, 1027, 6682, 2055, 10794, 2052, 14906, 1025, 1283, 2053,
                2054, 1281, 1282, 1026, 1537, 1538, 1539],
    "alpn": ["h2", "http/1.1"], "grease": True,
    "headers": {"accept": "*/*", "accept-language": "en-US,en;q=0.9",
                "sec-ch-ua-platform": "\"Windows\""},
    "http2": {"header_table_size": 65536},
}


@pytest.fixture
def policy():
    import copy
    return copy.deepcopy(MINI_POLICY)


@pytest.fixture
def profile_dict():
    import copy
    return copy.deepcopy(PROFILE_DICT)


@pytest.fixture
def vault():
    return CryptoVault(b"test-master-key-32-bytes-long!!")


@pytest.fixture
async def state(vault, tmp_path):
    st = AttackState(str(tmp_path / "state.db"), vault=vault)
    await st.init()
    yield st
    await st.close()


# ---------------------------------------------------------------- وكلاء وهمية
class FakeResponse:
    def __init__(self, status=200, text="", headers=None, body=None):
        self.status = status
        self._text = text
        self.headers = headers or {"content-type": "text/html"}
        self.body = body if body is not None else text.encode()
        self.url = "http://fake/"
        self.elapsed = 0.05

    @property
    def text(self):
        return self._text


class FakeCell:
    """خلية وهمية: transport يرد وفق جدول URL->Response."""
    def __init__(self, routes: dict | None = None):
        routes = routes or {}
        self.transport = self._Transport(routes)
        self.id = "test-cell"
        self.requests = 0
        self.failures = 0
        self.findings = 0

    class _Transport:
        def __init__(self, routes):
            self.routes = routes

        async def get(self, url, **kw):
            for prefix, resp in self.routes.items():
                if url.startswith(prefix):
                    return resp
            return FakeResponse(404, "not found")

        async def post(self, url, **kw):
            return FakeResponse(200, "{}")
