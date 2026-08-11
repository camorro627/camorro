"""تشفير الخزنة + سلسلة التجزئة + حالة الهجوم + الاسترداد بعد التلاعب."""
import pytest

from core.state_manager import Finding
from core.crypto_vault import CryptoVault


def test_seal_open_roundtrip(vault):
    blob = vault.seal(b"top secret")
    assert vault.open(blob) == b"top secret"
    assert blob != b"top secret"


def test_seal_open_string(vault):
    s = vault.seal_str("حمولة حقن: ' OR 1=1-- -")
    assert vault.open_str(s) == "حمولة حقن: ' OR 1=1-- -"


def test_tamper_detection(vault):
    blob = bytearray(vault.seal(b"payload"))
    blob[-1] ^= 0xFF
    with pytest.raises(Exception):
        vault.open(bytes(blob))


def test_stream_seal(vault):
    big = bytes(range(256)) * 100
    blob = vault.seal_stream(big)
    assert vault.open_stream(blob) == big


def test_hash_chain_detects_rewrite(vault):
    h0 = b"\x00" * 32
    h1 = vault.chain(h0, b"entry-1")
    h2 = vault.chain(h1, b"entry-2")
    # إعادة كتابة السجل الأول تكسر السلسلة
    h1_forged = vault.chain(h0, b"entry-1-FORGED")
    h2_forged = vault.chain(h1_forged, b"entry-2")
    assert h2 != h2_forged


@pytest.mark.asyncio
async def test_state_add_and_count(state):
    await state.add_finding(Finding(type="sql", severity="high", url="http://t/?id=1",
                                    param="id", payload="'", evidence="err"))
    await state.add_finding(Finding(type="xss", severity="medium", url="http://t/?q=1",
                                    param="q", payload="<svg>", evidence="ref"))
    assert await state.count_findings() == 2
    assert await state.count_findings("sql") == 1


@pytest.mark.asyncio
async def test_state_checkpoint_restore(state):
    await state.checkpoint("crawl_done", {"urls": ["a", "b"]})
    async with state._db.execute("SELECT value FROM meta WHERE key='crawl_done'") as cur:
        row = await cur.fetchone()
    import json
    data = json.loads(state.vault.open(row[0]).decode())
    assert data == {"urls": ["a", "b"]}
