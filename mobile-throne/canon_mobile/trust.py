from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class UntrustedKey(Exception):
    pass


class TrustStore:
    """Public-key-only trust store. Never creates keys or reads private material."""
    def __init__(self, root: Path, role: str = "release"):
        self.root = root.resolve()
        data = json.loads((self.root / "pinned.json").read_text(encoding="utf-8"))
        if not isinstance(data, dict) or role not in data:
            raise UntrustedKey(f"no pinned role: {role}")
        self.entry = data[role]
        self.role = role
        rel = Path(self.entry["file"])
        if rel.is_absolute():
            raise UntrustedKey("absolute trust-key paths are forbidden")
        self.key_path = (self.root / rel).resolve()
        if not self.key_path.is_relative_to(self.root):
            raise UntrustedKey("trust key escapes trust directory")
        self._key = self._load_key(self.key_path.read_bytes())
        self._raw = self._key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        actual = hashlib.sha256(self._raw).hexdigest()
        expected = self.entry.get("fingerprint", "")
        if not isinstance(expected, str) or not hmac.compare_digest(actual, expected):
            raise UntrustedKey(f"pinned fingerprint mismatch: expected {expected}, got {actual}")
        self._fingerprint = actual

    @staticmethod
    def _load_key(raw: bytes) -> Ed25519PublicKey:
        if raw.startswith(b"ssh-ed25519 "):
            key = serialization.load_ssh_public_key(raw.strip())
        elif b"-----BEGIN PUBLIC KEY-----" in raw:
            key = serialization.load_pem_public_key(raw)
        elif len(raw) == 32:
            key = Ed25519PublicKey.from_public_bytes(raw)
        else:
            raise UntrustedKey("unsupported public-key format; use raw 32-byte, PEM, or OpenSSH Ed25519")
        if not isinstance(key, Ed25519PublicKey):
            raise UntrustedKey("pinned key is not Ed25519")
        return key

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def public_key(self) -> Ed25519PublicKey:
        return self._key


class Verifier:
    def __init__(self, trust: TrustStore):
        self.trust = trust

    @property
    def fingerprint(self) -> str:
        return self.trust.fingerprint

    def verify(self, data: bytes, signature_b64: str) -> bool:
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            self.trust.public_key().verify(signature, data)
            return True
        except (ValueError, InvalidSignature):
            return False
