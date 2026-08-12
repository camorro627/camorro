#!/usr/bin/env bash
# ============================================================
# SwarmAttack Framework — مثبّت موحّد (Termux أندرويد + Linux)
# الاستخدام:  bash install.sh
# ============================================================
set -euo pipefail

PREFIX="${PREFIX:-}"
IS_TERMUX=0
if [[ "$PREFIX" == *"com.termux"* ]]; then
    IS_TERMUX=1
fi

echo "[*] البيئة المكتشفة: $([[ $IS_TERMUX -eq 1 ]] && echo 'Termux (أندرويد)' || echo 'Linux')"

# ------------------------------------------------------------ حزم النظام
if [[ $IS_TERMUX -eq 1 ]]; then
    echo "[*] تحديث Termux وتثبيت أدوات البناء..."
    pkg update -y && pkg upgrade -y
    pkg install -y python clang binutils pkg-config cmake ninja \
                   libcurl openssl rust libffi zlib libbrotli
else
    echo "[*] تثبيت أدوات البناء على Linux (إن لزم)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y python3 python3-venv python3-pip build-essential \
                           pkg-config libcurl4-openssl-dev libssl-dev \
                           libffi-dev rustc cargo
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip gcc gcc-c++ make pkg-config \
                       libcurl-devel openssl-devel libffi-devel rust cargo
    fi
fi

# ------------------------------------------------------------ Python >= 3.10
PY=$(command -v python3 || command -v python)
MAJOR=$("$PY" -c 'import sys; print(sys.version_info[0])')
MINOR=$("$PY" -c 'import sys; print(sys.version_info[1])')
if [[ "$MAJOR" -lt 3 || ( "$MAJOR" -eq 3 && "$MINOR" -lt 10 ) ]]; then
    echo "[!] يتطلب Python 3.10+ — الموجود: $("$PY" --version)"
    exit 1
fi

# ------------------------------------------------------------ البيئة الافتراضية (Linux فقط)
if [[ $IS_TERMUX -eq 0 ]] && [[ ! -x .venv/bin/python ]]; then
    echo "[*] إنشاء بيئة افتراضية .venv..."
    "$PY" -m venv .venv
    source .venv/bin/activate
    PY="python"
fi

echo "[*] ترقية pip..."
"$PY" -m pip install --upgrade pip

echo "[*] تثبيت المتطلبات الأساسية..."
if ! "$PY" -m pip install -r requirements.txt; then
    echo "[!] فشل التثبيت الأول — إعادة المحاولة بدون عزل البناء (مفيد على Termux)..."
    "$PY" -m pip install --no-build-isolation -r requirements.txt
fi

echo "[*] فحص محرك JA4..."
"$PY" swarm.py --self-test && \
echo "[+] تم التثبيت بنجاح — شغّل: python swarm.py --target https://example.com"
