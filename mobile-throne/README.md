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
