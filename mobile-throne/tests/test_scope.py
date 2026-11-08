from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from canon_mobile.scope import Engagement, RateLimiter, ScopeDenied, canonical_json


class FakeTrust:
    def __init__(self, key):
        self.key = key

    def public_key(self):
        return self.key


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "engagement.json"
        self.key = Ed25519PrivateKey.generate()
        self.body = {
            "version": 1,
            "engagement_id": "TEST-001",
            "in_scope": {
                "domains": ["example.org", "*.allowed.example.org"],
                "cidrs": ["192.0.2.0/24", "2001:db8::/32", "203.0.113.0/24"]
            },
            "out": ["blocked.example.org", "192.0.2.99", "198.51.100.0/24"],
            "roe": {
                "ports": [443, 8443],
                "protocols": ["tcp"],
                "max_requests_per_second": 1,
                "redirects": False
            }
        }
        self.write_engagement()
        self.engagement = Engagement(self.path, FakeTrust(self.key.public_key()))

    def tearDown(self):
        self.tmp.cleanup()

    def write_engagement(self):
        signature = self.key.sign(canonical_json(self.body))
        envelope = {
            "engagement": self.body,
            "signature_b64": base64.b64encode(signature).decode("ascii")
        }
        self.path.write_text(json.dumps(envelope), encoding="utf-8")

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_domain_resolves_and_pins_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("203.0.113.8", 443)),
            (2, 1, 6, "", ("203.0.113.8", 443))
        ]
        target = self.engagement.resolve("api.allowed.example.org", 443)
        self.assertEqual(target.addresses, ("203.0.113.8",))
        self.assertEqual(target.engagement_id, "TEST-001")
        self.assertEqual(target.port, 443)

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_domain_cannot_rebind_to_loopback(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("api.allowed.example.org", 443)

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_mixed_dns_answers_are_denied(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("203.0.113.8", 443)),
            (2, 1, 6, "", ("198.51.100.7", 443))
        ]
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("api.allowed.example.org", 443)

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_excluded_domain_is_denied(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("203.0.113.8", 443))]
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("blocked.example.org", 443)

    def test_ip_cidr_scope(self):
        target = self.engagement.resolve("192.0.2.15", 443)
        self.assertEqual(target.addresses, ("192.0.2.15",))

    def test_excluded_ip_is_denied(self):
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("192.0.2.99", 443)

    def test_unauthorized_port_is_denied(self):
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("192.0.2.15", 22)

    def test_rate_limiter_rejects_burst(self):
        target = self.engagement.resolve("192.0.2.15", 443)
        limiter = RateLimiter()
        limiter.acquire(target)
        with self.assertRaises(ScopeDenied):
            limiter.acquire(target)

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_dns_failure_is_denied(self, getaddrinfo):
        getaddrinfo.side_effect = OSError("NXDOMAIN")
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("api.allowed.example.org", 443)

    def test_redirect_disabled_by_default(self):
        target = self.engagement.resolve("192.0.2.15", 443)
        with self.assertRaises(ScopeDenied):
            self.engagement.validate_redirect(target, "https://example.org/next")

    def test_wildcard_does_not_match_parent_domain(self):
        with self.assertRaises(ScopeDenied):
            self.engagement.resolve("allowed.example.org", 443)

    def test_ipv6_cidr_scope(self):
        target = self.engagement.resolve("2001:db8::15", 443)
        self.assertEqual(target.addresses, ("2001:db8::15",))

    @patch("canon_mobile.scope.socket.getaddrinfo")
    def test_redirect_is_revalidated_when_explicitly_enabled(self, getaddrinfo):
        self.body["roe"]["redirects"] = True
        self.write_engagement()
        engagement = Engagement(self.path, FakeTrust(self.key.public_key()))
        origin = engagement.resolve("192.0.2.15", 443)
        getaddrinfo.return_value = [(2, 1, 6, "", ("203.0.113.8", 443))]
        redirected = engagement.validate_redirect(origin, "https://api.allowed.example.org/next")
        self.assertEqual(redirected.hostname, "api.allowed.example.org")
        self.assertEqual(redirected.addresses, ("203.0.113.8",))

    def test_redirect_to_out_of_scope_host_is_denied(self):
        self.body["roe"]["redirects"] = True
        self.write_engagement()
        engagement = Engagement(self.path, FakeTrust(self.key.public_key()))
        origin = engagement.resolve("192.0.2.15", 443)
        with patch("canon_mobile.scope.socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
            with self.assertRaises(ScopeDenied):
                engagement.validate_redirect(origin, "https://outside.invalid/")

    def test_tampered_engagement_signature_is_denied(self):
        envelope = json.loads(self.path.read_text(encoding="utf-8"))
        envelope["engagement"]["engagement_id"] = "TAMPERED"
        self.path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(ScopeDenied):
            Engagement(self.path, FakeTrust(self.key.public_key()))


if __name__ == "__main__":
    unittest.main()
