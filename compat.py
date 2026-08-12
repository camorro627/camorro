"""توافقية عبر المنصات: كشف بيئة التشغيل (Termux/أندرويد مقابل Linux) وضبط الموارد.

السبب: SwarmAttack يعمل على Linux (Kali) وTermux (أندرويد) — والهاتف أضعف
ذاكرةً ومعالجةً، ويفتقر لصلاحيات الجذر، وقد لا تتوفر فيه حزم اختيارية
مثل scapy وplaywright. كل الدوال هنا آمنة الاستيراد ولا تتطلب أي حزمة خارجية.
"""
import multiprocessing
import os
import platform
import sys

TERMUX_PREFIX = "/data/data/com.termux/files/usr"


def detect_environment() -> str:
    """يرجع 'termux' على أندرويد Termux، و'linux' على أنظمة Linux، و'other' غير ذلك."""
    if os.environ.get("PREFIX", "").startswith(TERMUX_PREFIX):
        return "termux"
    if os.environ.get("ANDROID_ROOT") and "com.termux" in (os.environ.get("HOME") or ""):
        return "termux"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


def is_termux() -> bool:
    return detect_environment() == "termux"


def platform_hint() -> str:
    env = detect_environment()
    if env == "termux":
        return "Termux (أندرويد)"
    if env == "linux":
        return f"Linux ({platform.machine()})"
    return platform.platform()


def default_max_cells(configured: int) -> int:
    """عدد خلايا آمن حسب البيئة: يقلل تلقائياً على الهواتف للحفاظ على الذاكرة."""
    if detect_environment() == "termux":
        cpu = multiprocessing.cpu_count()
        return max(2, min(configured, cpu // 2 or 1, 4))
    return min(configured, 24)


def memory_safe_queue() -> int:
    """حجم طابور آمن: أضيق على Termux لتقليل استهلاك الذاكرة."""
    return 1024 if detect_environment() == "termux" else 4096


def warn_optional(module_name: str, termux_pkg: str | None = None,
                  linux_pip: str | None = None) -> str:
    """رسالة إرشادية موحّدة عند غياب حزمة اختيارية (scapy/playwright)."""
    if detect_environment() == "termux" and termux_pkg:
        return (f"الحزمة '{module_name}' غير متوفرة على Termux.\n"
                f"  التثبيت:  pkg install {termux_pkg}\n"
                f"  ملاحظة: بعض الميزات (التقاط الحزم) تتطلب جذر/صلاحيات إضافية.")
    if linux_pip:
        return (f"الحزمة '{module_name}' غير مثبتة.\n"
                f"  التثبيت:  pip install {linux_pip}")
    return f"الحزمة '{module_name}' غير متوفرة في هذه البيئة."
