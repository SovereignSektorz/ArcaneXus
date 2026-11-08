from __future__ import annotations

from pathlib import Path

from .record import Record
from .schema import GENESIS
from .trust import Verifier


class ChainError(Exception):
    pass


def load(path: Path) -> list[Record]:
    if not path.exists():
        raise ChainError(f"chain file not found: {path}")
    records: list[Record] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise ChainError(f"blank line at {line_no}")
        try:
            records.append(Record.from_json(line))
        except Exception as exc:
            raise ChainError(f"invalid record at line {line_no}: {type(exc).__name__}: {exc}") from exc
    return records


def verify(path: Path, verifier: Verifier) -> list[Record]:
    records = load(path)
    if not records:
        raise ChainError("empty chain is not a sealed canon")
    previous = GENESIS
    for index, record in enumerate(records):
        if record.seq != index:
            raise ChainError(f"sequence mismatch at record {index}: {record.seq}")
        if record.prev != previous:
            raise ChainError(f"previous digest mismatch at record {index}")
        if not record.sig:
            raise ChainError(f"unsigned record at sequence {record.seq}")
        if not verifier.verify(record.body_bytes(), record.sig):
            raise ChainError(f"signature invalid at sequence {record.seq}")
        previous = record.body_digest()
    return records
