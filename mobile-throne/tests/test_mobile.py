from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from canon_mobile.chain import ChainError, verify
from canon_mobile.record import Record
from canon_mobile.receipts import ReceiptError, append, verify as verify_receipts
from canon_mobile.trust import TrustStore, Verifier
from canon_mobile.schema import GENESIS


class MobileCanonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.trust_dir = self.root / "trust"
        self.trust_dir.mkdir()
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (self.trust_dir / "release.pub").write_bytes(raw)
        import hashlib
        (self.trust_dir / "pinned.json").write_text(json.dumps({"release": {"file": "release.pub", "fingerprint": hashlib.sha256(raw).hexdigest()}}))
        self.verifier = Verifier(TrustStore(self.trust_dir, "release"))
        self.chain_path = self.root / "canon.jsonl"
        self.records = []
        previous = GENESIS
        for seq, article in enumerate(("A1", "A2", "A3")):
            rec = Record(seq, previous, article, {"sample": seq})
            rec = rec.with_sig(base64.b64encode(self.private.sign(rec.body_bytes())).decode())
            self.records.append(rec)
            previous = rec.body_digest()
        self.chain_path.write_text("\n".join(r.to_json() for r in self.records) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_chain(self):
        self.assertEqual(len(verify(self.chain_path, self.verifier)), 3)

    def test_signature_excluded_from_digest(self):
        rec = self.records[0]
        self.assertEqual(rec.body_digest(), rec.with_sig("different-signature-field").body_digest())

    def test_payload_tamper_rejected(self):
        rows = [json.loads(x) for x in self.chain_path.read_text().splitlines()]
        rows[1]["payload"]["sample"] = 999
        self.chain_path.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
        with self.assertRaises(ChainError):
            verify(self.chain_path, self.verifier)

    def test_record_reordering_rejected(self):
        self.chain_path.write_text(self.records[0].to_json() + "\n" + self.records[2].to_json() + "\n" + self.records[1].to_json() + "\n")
        with self.assertRaises(ChainError):
            verify(self.chain_path, self.verifier)

    def test_missing_record_rejected(self):
        self.chain_path.write_text(self.records[0].to_json() + "\n" + self.records[2].to_json() + "\n")
        with self.assertRaises(ChainError):
            verify(self.chain_path, self.verifier)

    def test_bad_signature_rejected(self):
        rows = [json.loads(x) for x in self.chain_path.read_text().splitlines()]
        rows[2]["sig"] = base64.b64encode(b"x" * 64).decode()
        self.chain_path.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
        with self.assertRaises(ChainError):
            verify(self.chain_path, self.verifier)

    def test_unpinned_key_rejected(self):
        data = json.loads((self.trust_dir / "pinned.json").read_text())
        data["release"]["fingerprint"] = "0" * 64
        (self.trust_dir / "pinned.json").write_text(json.dumps(data))
        with self.assertRaises(Exception):
            TrustStore(self.trust_dir, "release")

    def test_local_receipt_chain_and_tamper(self):
        path = self.root / "receipts.jsonl"
        append(path, "OBSERVATION", {"text": "one"})
        append(path, "OBSERVATION", {"text": "two"})
        self.assertEqual(verify_receipts(path)[0], 2)
        rows = [json.loads(x) for x in path.read_text().splitlines()]
        rows[0]["payload"]["text"] = "tampered"
        path.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
        with self.assertRaises(ReceiptError):
            verify_receipts(path)


if __name__ == "__main__":
    unittest.main()
