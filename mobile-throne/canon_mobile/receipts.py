from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .record import canonical_json

GENESIS = "0" * 64


class ReceiptError(Exception):
    pass


def verify(path: Path) -> tuple[int, str]:
    if not path.exists():
        return 0, GENESIS
    previous, count = GENESIS, 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            claimed = row.pop("event_hash")
            if row.get("sequence") != count + 1 or row.get("previous_hash") != previous:
                raise ReceiptError(f"sequence/previous hash mismatch at line {number}")
            actual = hashlib.sha256(canonical_json(row)).hexdigest()
            if actual != claimed:
                raise ReceiptError(f"digest mismatch at line {number}")
            previous, count = claimed, count + 1
        except ReceiptError:
            raise
        except Exception as exc:
            raise ReceiptError(f"invalid receipt line {number}: {type(exc).__name__}") from exc
    return count, previous


def append(path: Path, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not event_type or not isinstance(payload, dict):
        raise ValueError("event type and object payload required")
    path.parent.mkdir(parents=True, exist_ok=True)
    count, previous = verify(path)
    body = {
        "sequence": count + 1,
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous,
    }
    row = {**body, "event_hash": hashlib.sha256(canonical_json(body)).hexdigest()}
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return row
