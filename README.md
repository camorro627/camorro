<div align="center">

# 🐝 SwarmAttack Framework

**إطار اختبار اختراق عنقودي (Swarm) — بدل مهاجم واحد، سرب كامل.**

إطار متقدم بلغة **Python** يطلق **خلايا هجوم مستقلة**؛ كل خلية = بروكسي + بصمة TLS مطفَّرة + محرك سلوك بشري. تستهلك الخلايا المهام من طابور مركزي، فلا يصدر تدفق الطلبات من نقطة واحدة، ولا يحمل أي طلب بصمة المتسلل نفسه.

> **من إنشاء: Yassine — الملقب بـ Camorro**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#المتطلبات)
[![License](https://img.shields.io/badge/License-For%20Authorized%20Use%20Only-red.svg)](#⚠️-إشعار-قانوني-وأخلاقي)

</div>

---

## 📖 نظرة عامة

**SwarmAttack Framework** ليس ماسحاً تقليدياً يضرب هدفاً من عنوان IP واحد. هو **سرب (Swarm)** من الخلايا المتعاونة:

```
                        ┌─────────────────────────────────────┐
                        │           الطابور المركزي            │
                        │  crawl → sql → xss → bola → …        │
                        └───────────────┬─────────────────────┘
                                        │
              ┌─────────────┬───────────┼───────────┬─────────────┐
              ▼             ▼           ▼           ▼             ▼
        ┌──────────┐  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  خلية 01 │  │  خلية 02 │ │  خلية 03 │ │  خلية 04 │ │  خلية N │
        │ بروكسي A │  │ بروكسي B │ │ بروكسي C │ │ بروكسي D │ │   …      │
        │ بصمة Ch  │  │ بصمة Fx  │ │ بصمة Sa  │ │ بصمة Ed  │ │   …      │
        │ سلوك 1   │  │ سلوك 2   │ │ سلوك 3   │ │ سلوك 4   │ │   …      │
        └────┬─────┘  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
             └─────────────┴───────────┴─────────────┴───────────┘
                                        │
                              ┌─────────▼─────────┐
                              │    الهدف (Target)  │
                              └───────────────────┘
```

كل خلية تعمل كـ **هوية رقمية منفصلة** (وكيل بشري مختلف): بصمة TLS خاصة، بروكسي خاص، نمط سلوك مستقل — مع دائرة كهربائية (Circuit Breaker) وشفاء ذاتي عند فشل البروكسي.

---

## ✨ المميزات

### 🧬 1. خلايا هجوم عنقودية
- عدد خلايا قابل للضبط (`--cells`) مع **سقف ذكي حسب البيئة** (هاتف ≤ 4 خلايا حفاظاً على الذاكرة، سيرفر حتى 24).
- **دائرة كهربائية**: 6 إخفاقات متتالية ← إعادة تدوير البروكسي + فترة راحة تلقائية.
- **مراقب صحة (Watchdog)**: يكتشف الخلايا الميتة/الراكدة ويحييها ويدوّر بروكسياتها.

### 🔐 2. تزوير بصمة TLS (JA4)
- تزوير بصمة JA4 على مستوى الحزمة (ClientHello) وفق مواصفة **FoxIO**.
- قيم **GREASE** مستثناة من العد والتجزئة — مطابقة للسلوك الفعلي للمتصفحات.
- **إثبات ذاتي** (`--self-test`): يبني ClientHello ويحسب بصمته ويرى هل تطابق المتوقع نظرياً.
- **التقاط بصمات حقيقية** (`--capture-profile`): عبر scapy من متصفح تتحكم به (يتطلب root).

### 🌐 3. شبكة بروكسي دوّارة (Proxy Mesh)
- دوائر **لزجة** (Sticky) لكل خلية + فحص صحي غير متزامن (aiohttp).
- **عقوبات تلقائية**: البروكسي الميت يُحظر ويُستبدل فوراً.
- إعادة تدوير بعد عدد استخدامات قابل للضبط (`max_proxy_uses`).
- دعم `http://` و`socks5://` في ملف البروكسيات.

### 💉 4. محركات الحقن
| المحرك | الوصف |
|---|---|
| `sql` | حقن SQL بأنماطه الثلاثة: **خطأ (Error)** / **منطقي (Boolean)** / **زمني (Time)** مع تمويه الحمولات وكشف WAF |
| `xss` | انعكاس متعدد السياقات (سمة/نص/JS) + حمولة **Polyglot** + فحص **DOM** اختياري عبر Playwright |
| `bola` | كسر IDOR بالجوار الرقمي (Neighbors) + مقارنة متجهية للاستجابات لاكتشاف التفويض المعطوب |

### 🕷️ 5. زحف ذكي وتحليل JS
- قراءة `robots.txt` + `sitemap.xml` + استخراج الروابط + تخمين المسارات الشائعة.
- **تحليل حزم JavaScript** لاستخراج:
  - الأسرار: مفاتيح AWS، JWT، Stripe، GitHub tokens، مفاتيح Google، وغيرها.
  - نقاط API الجديدة (تُغذّى تلقائياً لمحركات الحقن).
  - الأنماط المشبوهة: `eval()`، `atob()`، `innerHTML=`، `postMessage()`…
- حد أقصى لحزم JS لكل خلية (5) لمنع انفجار الطابور.

### 🔒 6. حالة مشفرة بالكامل
- كل النتائج تُخزَّن **AES-256-GCM** داخل SQLite غير متزامن (aiosqlite).
- **سلسلة تكامل (Hash Chain)**: كل سجل يرتبط بسابقه — أي تلاعب يكسر السلسلة ويُكتشف.
- المفتاح من متغير بيئة (`SWARM_KEY`) أو ملف أو مطالبة — حسب `crypto.key_source`.

### 📊 7. تقارير ولوحة تحكم
- **لوحة تحكم حية** (Rich): خلايا/طلبات/نتائج/بروكسيات — تعمل حتى **بدون TTY** (تُعطَّل بصمت).
- تصدير **JSON مشفّر** (`.swarm.enc`) + **Markdown** قابل للقراءة مع سلسلة التجزئة.

### 📱 8. توافقية Termux + Linux (الجديد)
- كشف تلقائي للبيئة عبر `compat.py` (Termux / Linux / أخرى).
- تثبيت موحّد عبر `install.sh` يعمل على النظامين.
- استيرادات اختيارية آمنة: غياب `scapy` أو `playwright` لا يكسر الأداة أبداً.

---

## 📋 المتطلبات

| المتطلب | الحد الأدنى |
|---|---|
| Python | **3.10+** (الكود يستخدم أنماط `X \| Y` في التلميح) |
| نظام التشغيل | Linux (يُفضَّل Kali) / **Termux (أندرويد)** / macOS / Windows |
| الذاكرة | 2GB على الأقل (يُفضَّل 4GB على الهاتف) |
| الصلاحيات | root **فقط** لـ `--capture-profile` (يلزم scapy) |
| الحزم الاختيارية | `scapy` (للالتقاط) — `playwright` (لفحص DOM XSS) — **غير مطلوبة للتشغيل الأساسي** |

---

## 🚀 التثبيت

### الطريقة الموصى بها — المثبّت الموحّد (Linux + Termux)

```bash
git clone https://github.com/camorro627/camorro.git
cd camorro
bash install.sh
```

> المثبّت يكتشف البيئة تلقائياً: يثبّت حزم النظام المناسبة (pkg على Termux / apt أو dnf على Linux)، يتحقق من Python 3.10+، يثبّت المتطلبات (مع إعادة المحاولة بـ `--no-build-isolation` عند فشل البناء)، ثم يشغّل `--self-test` للتأكد.

### التثبيت اليدوي على Linux (Kali/Ubuntu/Debian)

```bash
git clone https://github.com/camorro627/camorro.git
cd camorro

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# إثبات ذاتي لمحرك JA4 (يُفضَّل أولاً)
python swarm.py --self-test
```

### التثبيت اليدوي على Termux (أندرويد)

```bash
pkg update -y && pkg upgrade -y
pkg install -y python clang binutils pkg-config cmake ninja \
               libcurl openssl rust libffi zlib libbrotli

git clone https://github.com/camorro627/camorro.git
cd camorro

pip install --upgrade pip
pip install -r requirements.txt        # أو: bash install.sh

# إثبات ذاتي لمحرك JA4
python swarm.py --self-test
```

**ملاحظات Termux:**
- لا حاجة لبيئة افتراضية — Termux يعزل باكاجاته تلقائياً.
- `scapy` و`playwright` **اختياريان** ولا يُثبَّتان افتراضياً:
  - `pkg install python-scapy` لتفعيل `--capture-profile` (يتطلب root/صلاحيات raw socket).
  - فحص DOM XSS يُتخطَّى تلقائياً عند غياب Playwright.
- عدد الخلايا يُخفَّض تلقائياً إلى ≤ 4 لحماية ذاكرة الهاتف — ارفعه يدوياً بـ `--cells` إن أردت.
- إن فشل تثبيت حزمة أثناء البناء من المصدر: أعد المحاولة بـ `pip install --no-build-isolation -r requirements.txt`.

---

## ⚡ الاستخدام السريع

```bash
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

# إثبات ذاتي لمحرك JA4
python swarm.py --self-test

# التقاط بصمة حقيقية من متصفحك (يتطلب scapy + صلاحيات)
sudo python swarm.py --capture-profile eth0

# بدون لوحة التحكم
python swarm.py --target https://example.com --no-dashboard
```

---

## 🛠️ مرجع وسائط سطر الأوامر (CLI)

| الوسيط | الوصف | الافتراضي |
|---|---|---|
| `--target, -t` | الهدف — يُكرر لعدة أهداف (**إلزامي**) | — |
| `--cells, -c` | عدد الخلايا (يتجاوز قيمة السياسة) | من السياسة |
| `--tests` | فاصلة: `sql,xss,bola` | من السياسة |
| `--policy-file` | مسار YAML بديل لسياسة الهجوم | `config/attack_policies.yaml` |
| `--proxy-file` | ملف بروكسيات (سطر لكل بروكسي: `http://…` أو `socks5://…`) | من السياسة |
| `--no-dashboard` | تعطيل لوحة التحكم الحية | مفعّلة |
| `--self-test` | اختبار محرك JA4 ثم الخروج | — |
| `--capture-profile IFACE` | التقاط ClientHello حقيقي من واجهة شبكة (scapy + root) | — |

---

## ⚙️ ملف السياسة — `config/attack_policies.yaml`

كل سلوكيات الهجوم قابلة للضبط دون لمس الكود:

```yaml
stealth:
  level: 5                  # 1..10 — كلما ارتفع: تأخيرات أطول، معدلات أقل
  max_cells: 8              # عدد الخلايا (يُخفَّض تلقائياً على Termux)
  delay_range: [1.2, 4.5]   # ثوانٍ بين الطلبات لكل خلية
  jitter: 0.35              # ضوضاء نسبية على كل تأخير
  think_time_range: [2.0, 9.0]   # محاكاة قراءة بشرية قبل الطلبات الحرجة
  max_rpm: 60               # أقصى طلب/دقيقة لكل خلية
  circuit_breaker: 6        # عدد الإخفاقات قبل إعادة تدوير البروكسي
  cooldown_after_rotate: [8, 20]  # ثوانٍ راحة بعد تغيير البروكسي

behavior:
  humanize: true
  scroll_probability: 0.25
  tab_switch_probability: 0.10

scope:
  allowed_domains: []       # فارغ = تقييد تلقائي بنطاق الهدف
  max_depth: 3
  max_urls: 500
  exclude_extensions: [".png", ".jpg", ".css", ".pdf", ...]

modules:
  enabled: [sql, xss, bola]
  sql:
    tests: [error, boolean, time]
    time_delay: 5           # ثوانٍ لحقن التأخير الزمني
    max_params_per_url: 20
  xss:
    dom_check: false        # يتطلب Playwright (يُتخطَّى تلقائياً على Termux)
    polyglot: true
  bola:
    neighbors: 10           # عدد المعرفات المجاورة لاختبارها
    batch_size: 25

network:
  proxy_file: null
  health_timeout: 6
  max_proxy_uses: 50
  dns_resolve: remote

crypto:
  key_source: env           # env | prompt | file
  key_env_var: SWARM_KEY
  state_encrypted: true

reporting:
  export_dir: ./reports
  log_level: INFO
```

**ملف بروكسيات مثال (`proxies.txt`):**

```text
http://127.0.0.1:8080
http://user:pass@proxy1.example.com:3128
socks5://127.0.0.1:9050
```

---

## 📁 هيكل المشروع

```
camorro/
├── swarm.py                      # نقطة الدخول الرئيسية (CLI)
├── compat.py                     # كشف البيئة (Termux/Linux) وضبط الموارد  ← جديد
├── install.sh                    # مثبّت موحّد للنظامين                     ← جديد
├── requirements.txt              # المتطلبات الأساسية + الاختيارية موثّقة
├── config/
│   ├── __init__.py               # محمّلات السياسات والبروفايلات
│   ├── attack_policies.yaml      # سياسة الهجوم (سلوك/تخفي/وحدات/تشفير)
│   └── network_profiles.json     # بصمات TLS حقيقية (Chrome/Firefox/Safari/Edge)
├── core/
│   ├── orchestrator.py           # الخلايا، الطابور، الدوائر، الشفاء الذاتي
│   ├── crypto_vault.py           # AES-256-GCM / ChaCha20 / Argon2id
│   └── state_manager.py          # SQLite غير متزامن مشفّر + سلسلة تكامل
├── modules/
│   ├── crawler/
│   │   ├── endpoint_map.py       # robots/sitemap/روابط/تخمين مسارات
│   │   └── js_analyzer.py        # أسرار JS + نقاط API + source maps
│   ├── evasion/
│   │   ├── ja4_mutator.py        # تزوير بصمة TLS (JA4) + الالتقاط (scapy)
│   │   ├── fingerprint_plus.py   # بصمات HTTP/2 وسلاسل الوكيل
│   │   ├── behavior_synth.py     # محرك السلوك البشري
│   │   └── proxy_mesh.py         # شبكة البروكسيات الدوّارة + الفحص الصحي
│   ├── injectors/
│   │   ├── sql_swarm.py          # SQLi: خطأ/منطقي/زمني + WAF
│   │   ├── xss_swarm.py          # XSS: انعكاس + polyglot + DOM (Playwright)
│   │   └── bola_logic.py         # كسر IDOR بالجوار والمقارنة المتجهية
│   └── exfil/                    # قنوات نقل مشفرة (DNS/HTTP/stego/relay)
├── ui/
│   ├── dashboard.py              # لوحة تحكم حية (Rich — بدون TTY)
│   └── logger.py                 # سجل + تقارير JSON مشفّر/Markdown
└── tests/                        # اختبارات الوحدات (pytest)
```

---

## 🔬 سير العمل النموذجي

1. **التهيئة**: تُقرأ السياسة، يُحمَّل المفتاح، تُبنى شبكة البروكسيات، تُفحص صحتها.
2. **الزحف**: كل هدف يدخل الطابور كـ `crawl` → خريطة نقاط (robots/روابط/تخمين) + تحليل JS.
3. **التغذية**: النقاط ذات البارامترات تُغذّي محركات الحقن (`sql`, `xss`, `bola`).
4. **الهجوم**: الخلايا تستهلك المهام عبر بروكسياتها وبصماتها وأنماط سلوكها مع تقييد معدل (Token Bucket).
5. **الحصاد**: النتائج تُشفَّر وتُخزَّن فوراً (AES-256-GCM + سلسلة تكامل) وتُدفع للوحة الحية.
6. **التقارير**: JSON مشفّر + Markdown في `reports/`.

---

## 🛟 استكشاف الأخطاء — الأسئلة الشائعة

| المشكلة | الحل |
|---|---|
| `ImportError: scapy` عند `--capture-profile` | Linux: `pip install scapy` — Termux: `pkg install python-scapy` (يلزم root) |
| فشل بناء حزمة أثناء `pip install` على Termux | أعد بـ `pip install --no-build-isolation -r requirements.txt` وتأكد من تثبيت `clang` و`rust` و`libffi` |
| البرنامج يبطئ على الهاتف | قلّل الخلايا: `--cells 2` — أو ارفع `delay_range` في السياسة |
| لوحة التحكم لا تظهر | عادي بدون TTY — استخدم `--no-dashboard` أو شغّل داخل محطة ملونة |
| `--self-test` يفشل | تأكد من `config/network_profiles.json` ومن Python 3.10+ |
| النتائج لا تُصدَّر | تأكد من متغير البيئة `SWARM_KEY` (أو عدّل `crypto.key_source` في السياسة) |
| لا بروكسيات متاحة | الأداة تعمل بدونها (اتصال مباشر) — أو أضف سطراً لكل بروكسي في `proxies.txt` |

---

## ⚠️ إشعار قانوني وأخلاقي

> **هذه الأداة مخصصة لاختبار الاختراق القانوني فقط**: الأصول التي تملكها، أو حصلت على إذن كتابي صريح لاختبارها (Bug Bounty، عقود اختبار اختراق، بيئات معملية). الاستخدام ضد أي نظام دون إذن يُعد **جريمة** في معظم الدول (قوانين مكافحة الجرائم المعلوماتية) ويعرّضك للمساءلة القانونية. أنت وحدك المسؤول عن استخدامك.

---

## 🗺️ خارطة الطريق (مقترحة)

- [ ] دعم خلايا موزعة عبر أجهزة متعددة (وضع الأسراب عن بُعد).
- [ ] محرك `command_injection` و`ssrf` و`xxe`.
- [ ] تكامل مع Burp Suite (استيراد/تصدير).
- [ ] حاويات Docker للخلايا.
- [ ] واجهة ويب للوحة التحكم.

---

## 👤 المؤلف

**Yassine — الملقب بـ Camorro**

---

## 📄 الرخصة

استخدام شخصي وتعليمي واختبارات مرخّصة فقط. انظر قسم الإشعار القانوني أعلاه.
