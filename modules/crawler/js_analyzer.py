"""تحليل ملفات JS: استخراج النقاط (endpoints)، مكالمات API، خرائط المصدر
(source maps)، وأنماط الأسرار (مفاتيح AWS/JWT/API tokens)."""
import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field

STRING_RE = re.compile(r'''(["'`])((?:\\.|(?!\1).)*)\1''')
ENDPOINT_RE = re.compile(r"(?:['\"`])((?:/|https?://)[A-Za-z0-9_\-./{}?&=:%+#]+)")
MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret", r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("stripe", r"sk_live_[0-9A-Za-z]{20,}"),
    ("google_api", r"AIza[0-9A-Za-z\-_]{30,}"),
    ("github_token", r"gh[pousr]_[0-9A-Za-z]{20,}"),
    ("slack", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("firebase", r"AIza[0-9A-Za-z\-_]{30,}"),
    ("generic_api", r"(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*[\"']([^\"']{12,})"),
]


@dataclass
class JS
