# SwarmAttack Framework

إطار اختبار اختراق **عنقودي (Swarm)** بلغة Python: بدل مهاجم واحد، تُطلق
**خلايا مستقلة** — كل خلية = بروكسي + بصمة TLS مطفَّرة + محرك سلوك بشري —
تستهلك المهام من طابور مركزي، فلا يصدر تدفق الطلبات من نقطة واحدة.

> **من إنشاء: Yassine — الملقب بـ Camorro**

---

## المميزات

- **خلايا هجوم** مستقلة بعدد قابل للضبط، مع دائرة كهربائية (circuit breaker) وشفاء ذاتي.
- **تزوير بصمة TLS (JA4)** على مستوى الحزمة + إثبات ذاتي (`--self-test`).
- **شبكة بروكسي دوّارة** مع دوائر لزجة، فحص صحي، وعقوبات تلقائية للبروكسيات الميتة.
- **محركات حقن**:
  - `sql` — خطأ / منطقي / زمني مع تمويه الحمولات وكشف WAF.
  - `xss` — انعكاس متعدد السياقات + حمولة polyglot + DOM اختياري عبر Playwright.
  - `bola` — كسر IDOR بالجوار الرقمي ومقارنة متجهية للاستجابات.
- **زحف ذكي**: robots/sitemap + استخراج الروابط + تخمين المسارات + تحليل JS
  لاستخراج الأسرار (AWS keys, JWT, tokens...) والنقاط الجديدة.
- **حالة مشفرة**: كل النتائج تُخزَّن AES-256-GCM (SQLite غير متزامن) مع سلسلة تكامل.
- **تقارير**: JSON مشفّر + Markdown قابل للقراءة.
- **لوحة تحكم حية** (Rich) تعمل حتى بدون TTY.

---

## المتطلبات

| المتطلب | الحد الأدنى |
|---|---|
| Python | 3.10+ |
| نظام تشغيل | Linux (يُفضَّل Kali) / macOS / Windows |
| صلاحيات | root فقط لـ `--capture-profile` (يلزم scapy) |

---

## التثبيت

```bash
git clone https://github.com/instagrmauwu/Gioioooo.git
cd Gioioooo

# (موصى به) بيئة افتراضية
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
# تشغيل أساسي بسياسات الملف الافتراضية
python swarm.py --target https://example.com

# تحديد عدد الخلايا والمحركات
python swarm.py --target https://example.com --cells 6 --tests sql,xss,bola

# عدة أهداف دفعة واحدة
python swarm.py -t https://a.com -t https://b.com

# سياسة مخصصة + ملف بروكسيات
python swarm.py --target https://example.com \
                --policy-file config/attack_policies.yaml \
                --proxy-file proxies.txt

# إثبات ذاتي لمحرك JA4 (يُفضَّل أولاً)
python swarm.py --self-test

# التقاط بصمة حقيقية من متصفحك (يتطلب scapy + صلاحيات)
sudo python swarm.py --capture-profile eth0

# بدون لوحة التحكم
python swarm.py --target https://example.com --no-dashboard
pip install -r requirements.
txt




الوسيط	الوصف
--target, -t	الهدف — يُكرر لعدة أهداف (إلزامي)
--cells, -c	عدد الخلايا (يتجاوز قيمة السياسة)
--tests	فاصلة: sql,xss,bola
--policy-file	مسار YAML بديل لسياسة الهجوم
--proxy-file	ملف بروكسيات (سطر لكل بروكسي: http://… أو socks5://…)
--no-dashboard	تعطيل لوحة التحكم الحية
--self-test	اختبار محرك JA4 ثم الخروج
--capture-profile IFACE	التقاط ClientHello حقيقي من واجهة شبكة (scapy)
الوسيط	الوصف
--target, -t	الهدف — يُكرر لعدة أهداف (إلزامي)
--cells, -c	عدد الخلايا (يتجاوز قيمة السياسة)
--tests	فاصلة: sql,xss,bola
--policy-file	مسار YAML بديل لسياسة الهجوم
--proxy-file	ملف بروكسيات (سطر لكل بروكسي: http://… أو socks5://…)
--no-dashboard	تعطيل لوحة التحكم الحية
--self-test	اختبار محرك JA4 ثم الخروج
--capture-profile IFACE	التقاط ClientHello حقيقي من واجهة شبكة (scapy)
---

**خطواتك الآن:**
1. استبدل محتوى `requirements.txt` بالمحتوى الجديد.
2. أنشئ `README.md` بالمحتوى أعلاه (عدّل اسم المؤلف/الرابط إن أردت).
3. أضف تعديل البروكسي في `orchestrator.py` إن كنت ستشغّل بدون بروكسيات.

هل تريد أن أفحص أيضاً ملف `tests/test_orchestrator.py` وأصححه ليتوافق مع التعديلات، أو أضيف مثالاً كاملاً لملف `proxies.txt`؟_

