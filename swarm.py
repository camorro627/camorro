#!/usr/bin/env python3
"""SwarmAttack Framework — نقطة الدخول الرئيسية.

الاستخدام:
  python swarm.py --target https://example.com --cells 6 --tests sql,xss,bola
  python swarm.py --target https://example.com --policy-file config/attack_policies.yaml
  python swarm.py --capture-profile        # التقاط بصمة حقيقية من متصفح (scapy)
  python swarm.py --self-test              # إثبات ذاتي لمحرك JA4
"""
import argparse
import asyncio
import json
import sys
import urllib.parse
from pathlib import Path

# ضمان استيراد الحزم من جذر المشروع
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import load_attack_policies, load_network_profiles
from core import AttackState, CryptoVault, Orchestrator
from core.orchestrator import Task
from core.state_manager import Finding
from modules.crawler.endpoint_map import EndpointMapper
from modules.crawler.js_analyzer import JSAnalyzer
from modules.evasion.ja4_mutator import (
    CaptureListener, TLSProfile, verify_mutation,
)
from modules.evasion.proxy_mesh import ProxyMesh
from modules.injectors import BOLALogic, SQLSwarm, XSSSwarm
from ui import Dashboard, EncryptedLogger

# المحركات القابلة للحقن فقط — استبعاد crawl حتى لا تُغذَّى الطابور بلا نهاية
INJECTABLE = ("sql", "xss", "bola")


def make_crawl_handler(orch: Orchestrator):
    """زحف + رسم خريطة نقاط + تحليل JS لكل نقطة، وتغذية طابور المهام بالمزيد.

    صُنعت كدالة مصنع (factory) تغلق على مرجع المنسق (orch) لأن AttackContext
    لا يحمل مرجعاً للمنسق ولا دالة submit — بديل صحيح وسليم
    لـ ctx.orchestrator_submit / ctx.queue_put غير الموجودتين أصلاً.
    """
    async def handle_crawl(cell, task, ctx) -> list[Finding]:
        findings: list[Finding] = []
        mapper = EndpointMapper(ctx.policy)
        js = JSAnalyzer(ctx.policy)

        enabled = set(ctx.policy["modules"]["enabled"])
        injectable = [m for m in INJECTABLE if m in enabled]

        records = await mapper.map_target(cell.transport, task.url)
        js_checked = 0
        for rec in records:
            if ctx.stop_event.is_set():
                break
            if rec.url.lower().endswith(".js"):
                if js_checked >= 5:          # حد أقصى لحزم JS لكل خلية
                    continue
                js_checked += 1
                report = await js.analyze_bundle(cell.transport, rec.url, depth=1)
                for rep in report:
                    for kind, val in rep.secrets[:3]:
                        findings.append(Finding(
                            type="js_secret",
                            severity="critical" if kind != "generic_api" else "medium",
                            url=rep.url, param=kind, payload=val[:80],
                            evidence=f"سر من نوع {kind} داخل حزمة JS",
                            confidence=0.9,
                        ))
                    # نقاط API المكتشفة داخل JS: إن حملت بارامترات نغذي محركات الحقن
                    for ep in rep.endpoints[:10]:
                        params = [
                            k for k, _ in urllib.parse.parse_qsl(
                                urllib.parse.urlparse(ep).query
                            )
                        ]
                        if params:
                            for mod in injectable:
                                await orch.submit(Task(
                                    kind=mod, url=ep, extra={"params": params},
                                ))
            # تغذية محركات الحقن من نقاط الزحف
            if rec.params:
                for mod in injectable:
                    await orch.submit(Task(
                        kind=mod, url=rec.url, extra={"params": rec.params},
                    ))
        return findings

    return handle_crawl


async def main() -> int:
    ap = argparse.ArgumentParser(description="SwarmAttack Framework — اختبار اختراق عنقودي")
    ap.add_argument("--target", "-t", action="append", help="الهدف (يُكرر لعدة أهداف)")
    ap.add_argument("--cells", "-c", type=int, default=None, help="عدد الخلايا (يتجاوز السياسة)")
    ap.add_argument("--tests", default=None, help="فاصلة: sql,xss,bola")
    ap.add_argument("--policy-file", default=None, help="مسار YAML سياسة بديل")
    ap.add_argument("--proxy-file", default=None, help="ملف بروكسيات (سطر لكل بروكسي)")
    ap.add_argument("--no-dashboard", action="store_true", help="تعطيل لوحة التحكم")
    ap.add_argument("--self-test", action="store_true", help="إثبات ذاتي لمحرك JA4 والخروج")
    ap.add_argument("--capture-profile", metavar="IFACE", default=None,
                    help="التقاط ClientHello حقيقي من واجهة شبكة (يتطلب scapy/صلاحيات)")
    args = ap.parse_args()

    # ---------------------------------------------------------- self-test
    if args.self_test:
        profiles = load_network_profiles()["profiles"]
        ok = 0
        for p in profiles:
            prof = TLSProfile.from_dict(p)
            good, observed, expected = verify_mutation(prof, "example.com")
            print(f"[{'OK' if good else 'FAIL'}] {prof.name}: observed={observed} expected={expected}")
            ok += good
        print(f"\n{ok}/{len(profiles)} اجتازوا حلقة الإثبات الذاتي")
        return 0 if ok == len(profiles) else 1

    # ---------------------------------------------------------- capture
    if args.capture_profile:
        listener = CaptureListener(iface=args.capture_profile)
        print(f"جارٍ الاستماع على {args.capture_profile}:443 لمدة 30 ثانية… (افتح متصفحك نحو أي HTTPS)")
        captured = listener.capture_one(timeout=30)
        print(json.dumps(captured, indent=2, ensure_ascii=False))
        return 0

    # ---------------------------------------------------------- التهيئة
    if not args.target:
        ap.error("مطلوب --target على الأقل (أو --self-test/--capture-profile)")
    policy = load_attack_policies()
    if args.policy_file:
        import yaml
        policy.update(yaml.safe_load(open(args.policy_file, encoding="utf-8")) or {})
    if args.cells:
        policy["stealth"]["max_cells"] = args.cells
    if args.tests:
        policy["modules"]["enabled"] = [t.strip() for t in args.tests.split(",") if t.strip()]

    vault = CryptoVault.from_env(policy["crypto"].get("key_env_var", "SWARM_KEY"))
    state = AttackState("./swarm_state.db", vault=vault)
    await state.init()

    logger = EncryptedLogger(vault, export_dir=policy["reporting"]["export_dir"])
    mesh = ProxyMesh.from_file(args.proxy_file or policy["network"].get("proxy_file"), policy)
    if mesh.records:
        await mesh.health_check_all()
        logger.info(f"فحص صحة البروكسيات: {mesh.stats()}")

    dashboard = Dashboard(state, mesh, enabled=not args.no_dashboard)
    orch = Orchestrator(policy, load_network_profiles()["profiles"], mesh,
                        vault, state, logger=logger, dashboard=dashboard)

    # ---------------------------------------------------------- ربط المحركات
    sql = SQLSwarm(policy)
    xss = XSSSwarm(policy)
    bola = BOLALogic(policy)
    orch.register_modules({
        "crawl": make_crawl_handler(orch),
        "sql": lambda cell, task, ctx: sql(cell, task, ctx),
        "xss": lambda cell, task, ctx: xss(cell, task, ctx),
        "bola": lambda cell, task, ctx: bola(cell, task, ctx),
    })

    # ---------------------------------------------------------- التشغيل
    logger.info("بدء SwarmAttack", targets=args.target, cells=policy["stealth"]["max_cells"])
    stop = asyncio.Event()
    dash_task = asyncio.create_task(dashboard.run(stop))
    try:
        await orch.run(args.target)
    finally:
        stop.set()
        await dash_task

    # ---------------------------------------------------------- التقارير
    findings_rows = []
    async with state._db.execute(
        "SELECT type, severity, url, param, payload_enc, evidence_enc, confidence, cell_id, ts FROM findings ORDER BY ts"
    ) as cur:
        async for row in cur:
            payload = vault.open(row[4]).decode(errors="replace") if (vault and row[4]) else ""
            evidence = vault.open(row[5]).decode(errors="replace") if (vault and row[5]) else ""
            findings_rows.append({
                "type": row[0], "severity": row[1], "url": row[2], "param": row[3],
                "payload": payload, "evidence": evidence, "confidence": row[6],
                "cell_id": row[7], "ts": row[8],
            })

    enc_path = logger.export_json_encrypted(findings_rows)
    md_path = logger.export_markdown(findings_rows, args.target[0])
    print(f"\n[+] النتائج ({len(findings_rows)}):")
    print(f"    تشفيرية: {enc_path}")
    print(f"    Markdown: {md_path}")
    await state.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
