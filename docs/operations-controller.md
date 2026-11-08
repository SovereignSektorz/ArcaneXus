# ArcaneXus Operations Controller

## Purpose

The controller produces a bounded, read-only evidence report for the rootless Termux workspace. It inventories top-level workspace entries, checks selected loopback ports, lists configured rclone remote names, and reads GitHub repository/PR/workflow metadata through an already authenticated `gh` CLI.

## Use on the XCover

```bash
ax ops
ax ops --json
ax ops --write-report
```

Direct invocation is also supported:

```bash
python3 ~/ArcaneXus/scripts/ax_ops.py
```

Timestamped reports are written under `~/ArcaneXus/reports/operations_controller/`. Existing reports are never overwritten.

## Permission boundary

- Automatic: local inventory, loopback TCP checks, GitHub read queries, and `rclone listremotes`.
- Not performed: remote Drive reads, synchronization, copy, file edits, cleanup, deletion, merges, deployments, permission changes, publication, or spending.
- Backup-named files are candidates for review, not proven duplicates.
- A listening port or readable repository is not proof of authorization, integrity, or production readiness.
- The controller never prints credentials, tokens, private keys, or raw authentication output.

## Verification

Run the unit tests from this repository checkout:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Run `bash -n termux/ax` to verify the launcher syntax. The deployed launcher is `~/.local/bin/ax`; preserve a timestamped backup before replacing it.

## Action-risk policy

`ax policy` displays the read-only risk classification. `ax policy check ACTION` classifies one named action. This is a classifier, not an authorization service or executor:

- L0 observation and L1 analysis require no approval when they remain read-only.
- L2 reversible operations require a narrow preauthorized scope. No scope registry or automatic L2 executor is active in this release.
- L3 consequential operations require explicit approval.
- Unknown actions fail closed to `REVIEW_REQUIRED`.

Do not interpret a classification as permission to execute. The current implementation does not grant capabilities, store approvals, or run the classified action.
