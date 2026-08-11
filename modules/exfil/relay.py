"""سلسلة ترحيل: أنفاق HTTP CONNECT متتابعة عبر عدة بروكسيات بحيث لا يظهر
المصدر الحقيقي في سجلات أي قفزة وحيدة (توزيع الخروج).
"""
import asyncio
import urllib.parse


class RelayError(RuntimeError):
    pass


class RelayChain:
    def __init__(self, proxies: list[str], timeout: float = 12.0):
        assert len(proxies) >= 1, "يلزم بروكسي واحد على الأقل"
        self.proxies = list(proxies)
        self.timeout = timeout

    @staticmethod
    def _parse(url: str) -> tuple[str, int]:
        """استخراج (host, port) من http:// أو socks5://."""
        p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        return p.hostname, p.port or (443 if p.scheme == "https" else 3128)

    def _connect_request(self, host: str, port: int, proxy: str) -> bytes:
        phost, pport = self._parse(proxy)
        auth = ""
        p = urllib.parse.urlparse(proxy if "://" in proxy else "http://" + proxy)
        if p.username:
            import base64
            token = base64.b64encode(f"{p.username}:{p.password or ''}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {token}\r\n"
        req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               f"Proxy-Connection: Keep-Alive\r\n"
               f"{auth}\r\n")
        return req.encode()

    async def open_tunnel(self, host: str, port: int) -> asyncio.StreamWriter:
        """فتح نفق عبر كل بروكسي بالتتابع؛ يعيد writer للقفزة الأخيرة."""
        loop = asyncio.get_running_loop()
        reader, writer = None, None
        try:
            for i, proxy in enumerate(self.proxies):
                phost, pport = self._parse(proxy)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(phost, pport), self.timeout)
                writer.write(self._connect_request(host, port, proxy))
                await writer.drain()
                # قراءة رأس الرد حتى نهاية السطرين
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = await asyncio.wait_for(reader.read(512), self.timeout)
                    if not chunk:
                        break
                    head += chunk
                status = head.split(b"\r\n", 1)[0].decode(errors="replace")
                if " 200 " not in status:
                    raise RelayError(
                        f"قفزة {i + 1} رفضت CONNECT: {status} — {self.proxies[i]}")
                # القفزات التالية تتصل عبر النفق الحالي
                host, port = phost, pport
            return writer
        except Exception:
            if writer:
                writer.close()
            raise

    async def relay_http(self, method: str, host: str, port: int,
                         request_bytes: bytes) -> bytes:
        """إرسال طلب HTTP خام عبر السلسلة وإرجاع الرد الكامل."""
        writer = await self.open_tunnel(host, port)
        try:
            writer.write(request_bytes)
            await writer.drain()
            resp = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(writer.read(65536), self.timeout)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 1 << 20:          # حد 1MB للأمان
                    break
            return resp
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
