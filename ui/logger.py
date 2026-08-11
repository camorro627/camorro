"""نظام التقارير: سجل خطي + تصدير JSON مشفّر (AES-GCM عبر CryptoVault) +
تصدير Markdown/HTML للتوثيق مع سلسلة تكامل (hash chain)."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path


class EncryptedLogger:
    def __init__(self, vault, export_dir: str = "./reports"):
        self.vault = vault
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self._chain = b"\x00" * 32          # سلسلة التجزئة (genesis)
        self._entries: list[dict] = []

    # ------------------------------------------------------------------ log
    def log(self, level: str, msg: str, **meta) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "msg": msg,
            "meta": meta,
        }
        self._entries.append(entry)
        line = json.dumps(entry, ensure_ascii=False)
        self._chain = self.vault.chain(self._chain, line.encode())
        # سطر نصي في الطرفية فقط للمستويات العليا
        if level in ("CRITICAL", "ERROR", "WARN"):
            print(f"[{level}] {msg}")

    def info(self, msg: str, **meta): self.log("INFO", msg, **meta)
    def warn(self, msg: str, **meta): self.log("WARN", msg, **meta)
    def error(self, msg: str, **meta): self.log("ERROR", msg, **meta)
    def critical(self, msg: str, **meta): self.log("CRITICAL", msg, **meta)

    # ------------------------------------------------------------------ export
    def export_json_encrypted(self, findings: list[dict], name: str = "findings") -> Path:
        blob = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "count": len(findings),
            "findings": findings,
            "chain_tail": self._chain.hex(),
        }
        payload = self.vault.seal(json.dumps(blob, ensure_ascii=False).encode())
        path = self.export_dir / f"{name}_{int(time.time())}.swarm.enc"
        path.write_bytes(payload)
        return path

    def export_markdown(self, findings: list[dict], target: str) -> Path:
        path = self.export_dir / f"report_{int(time.time())}.md"
        lines = [f"# SwarmAttack Report — {target}", "",
                 f"*{datetime.now(timezone.utc).isoformat()} — {len(findings)} نتيجة*", "",
                 "## الملخص", ""]
        summary: dict[str, int] = {}
        for f in findings:
            key = f"{f.get('type')}/{f.get('severity')}"
            summary[key] = summary.get(key, 0) + 1
        for k, v in sorted(summary.items()):
            lines.append(f"- **{k}**: {v}")
        lines += ["", "## التفاصيل", ""]
        for i, f in enumerate(findings, 1):
            lines += [
                f"### {i}. {f.get('type','').upper()} — {f.get('severity','')}",
                f"- **URL**: `{f.get('url')}`",
                f"- **البارامتر**: `{f.get('param') or '-'}`",
                f"- **الحمولة**: `{f.get('payload') or '-'}`",
                f"- **الدليل**: {f.get('evidence','')}",
                f"- **الثقة**: {f.get('confidence', 1.0):.0%}",
                f"- **الخلية**: {f.get('cell_id') or '-'}",
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
