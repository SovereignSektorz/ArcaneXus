from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ARTICLE = re.compile(r"^A(?:[1-9]|1[0-3])$")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class Record:
    seq: int
    prev: str
    article: str
    payload: dict[str, Any]
    sig: str = ""

    def __post_init__(self) -> None:
        if type(self.seq) is not int or self.seq < 0:
            raise ValueError("seq must be a non-negative integer")
        if not isinstance(self.prev, str) or not _HEX64.fullmatch(self.prev):
            raise ValueError("prev must be a lowercase SHA-256 digest")
        if not isinstance(self.article, str) or not _ARTICLE.fullmatch(self.article):
            raise ValueError("article must be A1 through A13")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be an object")
        if not isinstance(self.sig, str):
            raise ValueError("sig must be a string")

    def body(self) -> dict[str, Any]:
        # Detached signatures are deliberately excluded from the hashed body.
        return {"seq": self.seq, "prev": self.prev, "article": self.article, "payload": self.payload}

    def body_bytes(self) -> bytes:
        return canonical_json(self.body())

    def body_digest(self) -> str:
        return hashlib.sha256(self.body_bytes()).hexdigest()

    def with_sig(self, signature: str) -> "Record":
        return Record(self.seq, self.prev, self.article, self.payload, signature)

    def to_json(self) -> str:
        return canonical_json({**self.body(), "sig": self.sig}).decode("utf-8")

    @classmethod
    def from_json(cls, line: str) -> "Record":
        value = json.loads(line)
        if not isinstance(value, dict) or set(value) != {"seq", "prev", "article", "payload", "sig"}:
            raise ValueError("record keys must be exactly seq, prev, article, payload, sig")
        return cls(value["seq"], value["prev"], value["article"], value["payload"], value["sig"])
