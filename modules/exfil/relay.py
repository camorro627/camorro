"""سلسلة ترحيل: أنفاق HTTP CONNECT متتابعة عبر عدة بروكسيات بحيث لا يظهر
المصدر الحقيقي في سجلات أي قفزة وحيدة (توزيع الخروج).
"""
import asyncio
import urllib.parse


class RelayError(RuntimeError):
    pass


class RelayChain:
    def __init__(self, proxies: list[str], timeout: float = 12.0):
        assert len(proxies) >= 1,
