from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from .trust import TrustStore


class ScopeDenied(Exception):
    """A target or operation is outside the signed engagement."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hostname(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or any(ch in value for ch in "/\\\\@?#"):
        raise ScopeDenied("invalid hostname")
    try:
        ascii_host = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeDenied("invalid IDNA hostname") from exc
    if len(ascii_host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in ascii_host.split(".")
    ):
        raise ScopeDenied("invalid hostname label")
    return ascii_host


def _domain_match(host: str, patterns: list[str]) -> bool:
    host = _hostname(host)
    for raw in patterns:
        pattern = raw.strip().lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = _hostname(pattern[2:])
            if host.endswith("." + suffix) and host != suffix:
                return True
        elif "*" in pattern:
            raise ScopeDenied("only a leading '*.' domain wildcard is supported")
        elif host == _hostname(pattern):
            return True
    return False


def _parse_networks(items: list[str]) -> list[Any]:
    try:
        return [ipaddress.ip_network(item, strict=False) for item in items]
    except (ValueError, TypeError) as exc:
        raise ScopeDenied(f"invalid CIDR in engagement: {exc}") from exc


def _ip_match(address: str, networks: list[Any]) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip.version == net.version and ip in net for net in networks)


def _excluded(host: str, addresses: list[str], exclusions: list[str]) -> bool:
    try:
        ipaddress.ip_address(host)
        host_is_ip = True
    except ValueError:
        host_is_ip = False
    for item in exclusions:
        item = str(item).strip()
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            if not host_is_ip:
                try:
                    if _domain_match(host, [item]):
                        return True
                except ScopeDenied:
                    raise
            try:
                excluded_ip = ipaddress.ip_address(item)
                if any(ipaddress.ip_address(addr) == excluded_ip for addr in addresses):
                    return True
            except ValueError:
                pass
        else:
            if any(ipaddress.ip_address(addr).version == net.version and ipaddress.ip_address(addr) in net
                   for addr in addresses):
                return True
    return False


@dataclass(frozen=True)
class PinnedTarget:
    requested: str
    hostname: str
    addresses: tuple[str, ...]
    port: int
    protocol: str
    engagement_id: str
    engagement_sha256: str
    validated_at: int
    expires_at: int
    redirects_allowed: bool
    max_requests_per_second: float


class RateLimiter:
    """In-process fail-closed limiter; one instance must be shared by an adapter."""
    def __init__(self):
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, target: PinnedTarget) -> None:
        if int(time.time()) >= target.expires_at:
            raise ScopeDenied("scope authorization expired")
        key = target.engagement_sha256
        interval = 1.0 / target.max_requests_per_second
        with self._lock:
            now_mono = time.monotonic()
            previous = self._last.get(key)
            if previous is not None and now_mono - previous < interval:
                raise ScopeDenied("engagement request-rate limit exceeded")
            self._last[key] = now_mono


class Engagement:
    """Verifies a signed engagement using a pinned public key only.

    Envelope format:
      {"engagement": {...}, "signature_b64": "..."}
    Signature covers canonical_json(engagement).
    """

    def __init__(self, path: Path, trust: TrustStore):
        self.path = path.resolve()
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            body = envelope["engagement"]
            signature = envelope["signature_b64"]
            if not isinstance(body, dict) or not isinstance(signature, str):
                raise ValueError("invalid envelope fields")
            trust.public_key().verify(base64.b64decode(signature, validate=True),
                                      canonical_json(body))
        except (OSError, ValueError, KeyError, TypeError, InvalidSignature) as exc:
            raise ScopeDenied(f"engagement signature or format invalid: {exc}") from exc
        self.body = body
        self.digest = sha256(canonical_json(body))
        self._validate_schema()

    def _validate_schema(self) -> None:
        body = self.body
        if body.get("version") != 1 or not isinstance(body.get("engagement_id"), str):
            raise ScopeDenied("unsupported engagement version or missing engagement_id")
        scope = body.get("in_scope")
        roe = body.get("roe")
        if not isinstance(scope, dict) or not isinstance(roe, dict):
            raise ScopeDenied("in_scope and roe objects are required")
        domains = scope.get("domains", [])
        cidrs = scope.get("cidrs", [])
        if not isinstance(domains, list) or not isinstance(cidrs, list) or not (domains or cidrs):
            raise ScopeDenied("at least one explicit domain or CIDR scope is required")
        for domain in domains:
            if not isinstance(domain, str):
                raise ScopeDenied("domain entries must be strings")
            _domain_match("scope-validation.invalid", [domain]) if domain.startswith("*.") else _hostname(domain)
        _parse_networks(cidrs)
        exclusions = body.get("out", [])
        if not isinstance(exclusions, list) or any(not isinstance(x, str) for x in exclusions):
            raise ScopeDenied("out exclusions must be a list of strings")
        _parse_networks([x for x in exclusions if "/" in x])
        ports = roe.get("ports")
        if not isinstance(ports, list) or not ports:
            raise ScopeDenied("roe.ports must be an explicit non-empty integer list")
        if any(type(p) is not int or p < 1 or p > 65535 for p in ports):
            raise ScopeDenied("invalid port in ROE")
        protocols = roe.get("protocols", [])
        if not isinstance(protocols, list) or not protocols or any(p not in ("tcp",) for p in protocols):
            raise ScopeDenied("only explicitly declared TCP is currently supported")
        rate = roe.get("max_requests_per_second", 0)
        if type(rate) not in (int, float) or not math.isfinite(rate) or rate <= 0:
            raise ScopeDenied("finite positive max_requests_per_second is required")
        if type(roe.get("redirects", False)) is not bool:
            raise ScopeDenied("roe.redirects must be boolean")

    def resolve(self, target: str, port: int, protocol: str = "tcp", ttl_s: int = 30) -> PinnedTarget:
        if not 1 <= int(port) <= 65535:
            raise ScopeDenied("invalid destination port")
        roe = self.body["roe"]
        if int(port) not in roe["ports"]:
            raise ScopeDenied(f"port {port} is not authorized")
        if protocol not in roe["protocols"]:
            raise ScopeDenied(f"protocol {protocol} is not authorized")

        raw = target.strip()
        if not raw:
            raise ScopeDenied("empty target")
        # Accept a hostname or a bare IP only; URLs and host:port forms are rejected.
        if "://" in raw or "/" in raw or "@" in raw:
            raise ScopeDenied("target must be a bare hostname or IP address")
        try:
            literal = ipaddress.ip_address(raw.strip("[]"))
            host = literal.compressed
            addresses = [literal.compressed]
        except ValueError:
            host = _hostname(raw)
            try:
                answers = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            except OSError as exc:
                raise ScopeDenied(f"DNS resolution failed: {exc}") from exc
            addresses = sorted({ipaddress.ip_address(row[4][0]).compressed for row in answers})
            if not addresses:
                raise ScopeDenied("DNS returned no usable addresses")

        scope = self.body["in_scope"]
        domains_ok = False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            domains_ok = _domain_match(host, scope.get("domains", []))
        networks = _parse_networks(scope.get("cidrs", []))
        address_results = []
        for addr in addresses:
            ip = ipaddress.ip_address(addr)
            # A domain grant does not authorize DNS rebinding to private, loopback,
            # link-local, multicast, or reserved address space. Such addresses need
            # an explicit matching CIDR in the signed engagement.
            address_results.append(_ip_match(addr, networks) or (domains_ok and ip.is_global))
        if not all(address_results):
            raise ScopeDenied("target or one or more DNS answers are outside declared scope")
        if _excluded(host, addresses, self.body.get("out", [])):
            raise ScopeDenied("target or resolved address is explicitly excluded")

        now = int(time.time())
        return PinnedTarget(
            requested=target, hostname=host, addresses=tuple(addresses),
            port=int(port), protocol=protocol,
            engagement_id=self.body["engagement_id"], engagement_sha256=self.digest,
            validated_at=now, expires_at=now + max(1, min(int(ttl_s), 300)),
            redirects_allowed=bool(roe.get("redirects", False)),
            max_requests_per_second=float(roe["max_requests_per_second"]),
        )

    def validate_redirect(self, original: PinnedTarget, location: str) -> PinnedTarget:
        if not original.redirects_allowed:
            raise ScopeDenied("redirects are disabled by the engagement")
        if int(time.time()) >= original.expires_at:
            raise ScopeDenied("original scope authorization expired")
        parsed = urlsplit(location)
        if (parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ScopeDenied("redirect must be an absolute HTTPS URL without userinfo")
        try:
            port = parsed.port or 443
        except ValueError as exc:
            raise ScopeDenied("invalid redirect port") from exc
        return self.resolve(parsed.hostname, port, "tcp", max(1, original.expires_at - int(time.time())))


def validate_target(engagement_path: Path, trust_dir: Path, target: str,
                    port: int, role: str = "engagement") -> PinnedTarget:
    trust = TrustStore(trust_dir, role)
    engagement = Engagement(engagement_path, trust)
    return engagement.resolve(target, port)
