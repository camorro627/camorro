"""محمل الإعدادات الموحد: ملفات تعريف الشبكات + سياسات الهجوم."""
from pathlib import Path
import json

import yaml

CONFIG_DIR = Path(__file__).resolve().parent


def load_network_profiles() -> dict:
    with open(CONFIG_DIR / "network_profiles.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_attack_policies() -> dict:
    with open(CONFIG_DIR / "attack_policies.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
