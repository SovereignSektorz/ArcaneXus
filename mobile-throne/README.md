# ArcaneXus Mobile Throne Node

**CANON v1 mobile verifier profile | rootless Termux | development / unverified until external evidence exists**

This package installs a bounded XCover node. It verifies a signed CANON chain against a pinned Ed25519 public key and keeps a separate local hash-chained observation receipt log.

## Authority boundary

- The XCover stores public trust material only. No release private key is generated or imported.
- It cannot sign canon promotions, authorize execution, or change ArcaneXus authority.
- It does not host the 7B inference lanes. Inference and canonical promotion remain on appropriately provisioned infrastructure.
- Remote Desktop Commander is the operator-mediated transport. It is not an authority grant.
- Local receipts are tamper-evident hash chains, not detached signatures and not proof of physical truth.

## Install on the XCover

From the cloned ArcaneXus repository root:

```bash
bash mobile-throne/scripts/install-termux.sh
```

Then run:

```bash
ax-throne status
python -m unittest discover -s "$HOME/.local/share/arcanexus-mobile-throne/tests" -v
```

## Verify a release chain

Copy the release `canon.jsonl`, `trust/pinned.json`, and matching public key to the phone using an authenticated transfer. Never copy `release.key` or any private key.

```bash
ax-throne verify \
  --chain "$HOME/ArcaneXus/inbox/canon.jsonl" \
  --trust-dir "$HOME/ArcaneXus/inbox/trust" \
  --role release
```

The fingerprint in `pinned.json` must be independently checked out of band. A public key shipped beside an untrusted chain is not automatically trusted.

## Local receipts

```bash
ax-throne receipt --text "Observed release package" --source "STEWARD_INPUT"
ax-throne receipt-verify
```

These receipts do not promote a release.

## Remote Desktop Commander persistence

The installer adds an idempotent Termux:Boot hook at `~/.termux/boot/05_arcanexus_rdc.sh`. It starts the existing remote agent only when no agent process is found, under tmux session `rdc`, and requests a wake lock. Android battery management can still stop background work; set Termux and Termux:Boot to unrestricted battery use and enable the Termux:Boot app's background-start permission.

Check access with:

```bash
tmux ls
pgrep -af 'desktop-commander|wonderwhy-er'
```

## Verification scope

The mobile package implements public-key trust, canonical record hashing, full chain verification, and local receipt verification. It does **not** claim all thirteen external CANON gates have passed. Three independent witnesses, clean-clone reconstruction, toolchain/model inventory, and external audit remain release-host responsibilities.

## Signed engagement scope guard

The `canon_mobile.scope` module is a deny-by-default target validator. It verifies a signed engagement using the public-only `engagement` trust role, validates every A/AAAA answer, applies exact domain/CIDR scope and explicit exclusions, checks explicit TCP ports, and returns a short-lived immutable `PinnedTarget`. It never initiates a connection.

Engagement envelope format:

```json
{
  "engagement": {
    "version": 1,
    "engagement_id": "AUTHORIZED-ENGAGEMENT-ID",
    "in_scope": {
      "domains": ["example.org", "*.authorized.example.org"],
      "cidrs": ["192.0.2.0/24", "2001:db8::/32", "203.0.113.0/24"]
    },
    "out": ["excluded.example.org", "192.0.2.9", "198.51.100.0/24"],
    "roe": {
      "ports": [443],
      "protocols": ["tcp"],
      "max_requests_per_second": 1,
      "redirects": false
    }
  },
  "signature_b64": "BASE64_ED25519_SIGNATURE_OVER_CANONICAL_ENGAGEMENT_JSON"
}
```

The example IP ranges are reserved documentation ranges, not real targets. The signature is Ed25519 over UTF-8 JSON serialized with sorted keys and compact separators. The matching public key must be pinned out of band in `trust/pinned.json` under role `engagement`; the private key must remain with the engagement authority and must never be placed on the XCover.

Non-invasive scope check (DNS resolution only; no port connection or scan):

```bash
ax-throne scope-check \
  --engagement "$HOME/ArcaneXus/inbox/engagement.json" \
  --trust-dir "$HOME/ArcaneXus/inbox/trust" \
  --role engagement \
  --port 443 \
  api.authorized.example.org
```

A successful result reports `connected: false` and the exact resolved addresses that a future adapter must pin. Network adapters must consume that returned address set directly, preserve the original hostname for TLS SNI/certificate validation, reject expired pins, and call `Engagement.validate_redirect()` for every redirect. They must not perform a second DNS lookup. No current mobile-throne command performs network scanning or uses this result to connect.

Redirects are denied unless the signed engagement sets `roe.redirects` to `true`; each permitted redirect must be an absolute HTTPS URL and must independently pass the same scope, exclusion, port, and DNS checks. Only explicit integer ports are accepted. Shorthand policies such as `top1000`, `all`, and `any` are intentionally unsupported.

This is a technical scope control, not proof of legal authorization. Use only engagements approved by the owners of the target systems.

The scope result also carries the signed request-rate ceiling. A network adapter must share one RateLimiter instance for the full engagement and call acquire(pinned_target) before every request. The current limiter is process-local; multi-process or distributed adapters require a shared transactional limiter before they can claim the ROE rate ceiling is enforced.

Additional DNS safety: a domain entry does not authorize rebinding to private, loopback, link-local, multicast, or reserved address space. Such answers require an explicit matching CIDR in the signed engagement. The in-process RateLimiter is a required adapter hook, not a distributed rate-control service; a multi-process adapter must replace it with shared transactional state.

Additional DNS safety: a domain entry does not authorize rebinding to private, loopback, link-local, multicast, or reserved address space. Such answers require an explicit matching CIDR in the signed engagement. The in-process RateLimiter is a required adapter hook, not a distributed rate-control service; a multi-process adapter must replace it with shared transactional state.
