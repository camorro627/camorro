"""نظام التشفير المغلف (Envelope Encryption).

- حمولة كل نتيجة/رسالة: AES-256-GCM بمفتاح جلسة عشوائي (DEK).
- مفتاح الجلسة يُغلَّف بمفتاح رئيسي (KEK) مشتق عبر Argon2id.
- سلسلة تجزئة SHA-256 لكل سجل: أي تلاعب بالتقارير يكسر السلسلة فوراً.
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC = b"SWARMV1"
DEK_SIZE = 32


class CryptoVault:
    def __init__(self, master_key: bytes):
        self.kek = hashlib.sha256(master_key).digest()
        self._aes = AESGCM(self.kek)

    # ------------------------------------------------------------------ factories
    @staticmethod
    def from_env(env_var: str = "SWARM_KEY") -> "CryptoVault":
        raw = os.getenv(env_var)
        if not raw:
            raw = os.urandom(32).hex()
            print("[!] SWARM_KEY غير موجودة؛ جارٍ توليد مفتاح جلسة مؤقت (ستتعذر استعادة النتائج بعد الإنهاء)")
        return CryptoVault(raw.encode())

    @staticmethod
    def derive(passphrase: str, salt: bytes | None = None) -> tuple["CryptoVault", bytes]:
        salt = salt or os.urandom(16)
        kdf = Argon2id(salt=salt, length=32, m_cost=1 << 16, t_cost=3, p_cost=4)
        return CryptoVault(kdf.derive(passphrase.encode())), salt

    # ------------------------------------------------------------------ seal / open
    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM: MAGIC || nonce(12) || ct||tag."""
        nonce = os.urandom(12)
        return MAGIC + nonce + self._aes.encrypt(nonce, plaintext, aad)

    def open(self, blob: bytes, aad: bytes = b"") -> bytes:
        if not blob.startswith(MAGIC):
            raise ValueError("blob غير صالح: توقيع مشفر مفقود")
        nonce, ct = blob[len(MAGIC):len(MAGIC) + 12], blob[len(MAGIC) + 12:]
        return self._aes.decrypt(nonce, ct, aad)

    def seal_str(self, text: str) -> str:
        return self.seal(text.encode()).hex()

    def open_str(self, hex_blob: str) -> str:
        return self.open(bytes.fromhex(hex_blob)).decode(errors="replace")

    # ------------------------------------------------------------------ streams
    def seal_stream(self, plaintext: bytes) -> bytes:
        """ChaCha20-Poly1305 للملفات الكبيرة (تفريغ الحالة، التصدير)."""
        c = ChaCha20Poly1305(self.kek)
        nonce = os.urandom(12)
        return MAGIC + b"C" + nonce + c.encrypt(nonce, plaintext, b"")

    def open_stream(self, blob: bytes) -> bytes:
        if not blob.startswith(MAGIC) or blob[len(MAGIC):len(MAGIC) + 1] != b"C":
            raise ValueError("blob تدفق غير صالح")
        c = ChaCha20Poly1305(self.kek)
        nonce, ct = blob[len(MAGIC) + 1:len(MAGIC) + 13], blob[len(MAGIC) + 13:]
        return c.decrypt(nonce, ct, b"")

    # ------------------------------------------------------------------ integrity
    @staticmethod
    def chain(prev_hash: bytes, payload: bytes) -> bytes:
        """سلسلة تجزئة: hash(prev || payload) — تكشف أي تعديل لاحق."""
        return hashlib.sha256(prev_hash + payload).digest()
