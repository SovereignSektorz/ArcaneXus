#!/usr/bin/env python3
"""ArcaneXus Operations Controller: bounded, read-only health and evidence report.

No mutation, cleanup, synchronization, deployment, merge, or privilege escalation
is performed. Optional report output is written only when --write-report is used.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ax_policy import POLICY as ACTION_POLICY

DEFAULT_REPOS = (
    "SovereignSektorz/ArcaneXus",
    "SovereignSektorz/ArcaneXus-Public",
    "covnfrequency-unity/Arcanexus_OS",
)
PORTS = (1121, 1124, 11434)
SKIP_DIRS = {
    ".git", ".pytest_cache", "__pycache__", ".venv", "venv",
    "node_modules", "build", "dist", ".gradle",
}
BACKUP_MARKERS = (".bak", ".backup", ".old", ".pre_", ".before_", ".copy")


def run(args: list[str], timeout: int = 8) -> dict[str, Any]:
    """Run a bounded read-only command without exposing raw stderr/stdout."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return {"available": True, "returncode": proc.returncode, "stdout": proc.stdout}
    except FileNotFoundError:
        return {"available": False, "returncode": None, "stdout": ""}
    except subprocess.TimeoutExpired:
        return {"available": True, "returncode": 124, "stdout": ""}


def port_state(port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.35)
    try:
        return "LISTENING" if sock.connect_ex(("127.0.0.1", port)) == 0 else "NOT_REACHABLE"
    finally:
        sock.close()


def workspace_inventory(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        return {"state": "NOT_FOUND", "path": str(root)}
    entries: list[dict[str, Any]] = []
    duplicate_candidates: list[str] = []
    try:
        children = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return {"state": "INACCESSIBLE", "path": str(root)}
    for item in children:
        if item.name in SKIP_DIRS or item.is_symlink():
            continue
        try:
            if item.is_dir():
                count = 0
                subdirs = 0
                for child in item.iterdir():
                    if child.is_symlink() or child.name in SKIP_DIRS:
                        continue
                    if child.is_file():
                        count += 1
                        low = child.name.lower()
                        if any(mark in low for mark in BACKUP_MARKERS):
                            duplicate_candidates.append(str(child.relative_to(root)))
                    elif child.is_dir():
                        subdirs += 1
                entries.append({
                    "name": item.name, "kind": "directory",
                    "direct_files": count, "direct_subdirectories": subdirs,
                })
            elif item.is_file():
                entries.append({"name": item.name, "kind": "file", "bytes": item.stat().st_size})
                low = item.name.lower()
                if any(mark in low for mark in BACKUP_MARKERS):
                    duplicate_candidates.append(item.name)
        except OSError:
            entries.append({"name": item.name, "kind": "unreadable"})
    return {
        "state": "PRESENT",
        "path": str(root),
        "git_checkout": (root / ".git").exists(),
        "master_spec_present": (root / "00_Void" / "UNIFIED_REALITY_SPEC.md").is_file(),
        "top_level_entries": len(entries),
        "entries": entries,
        "backup_named_candidates": sorted(duplicate_candidates),
        "note": "Name-based candidates only; no content was compared and nothing was changed.",
    }


def github_readonly() -> dict[str, Any]:
    gh = shutil.which("gh")
    if not gh:
        return {"state": "CLI_NOT_INSTALLED", "repos": []}
    auth = run([gh, "auth", "status"], timeout=5)
    if auth["returncode"] != 0:
        return {"state": "CLI_NOT_AUTHENTICATED", "repos": []}
    results = []
    for repo in DEFAULT_REPOS:
        view = run([
            gh, "repo", "view", repo,
            "--json", "nameWithOwner,url,defaultBranchRef",
        ])
        if view["returncode"] != 0:
            results.append({"repository": repo, "state": "UNAVAILABLE"})
            continue
        try:
            metadata = json.loads(view["stdout"] or "{}")
        except json.JSONDecodeError:
            metadata = {}
        prs = run([
            gh, "pr", "list", "--repo", repo, "--state", "open",
            "--limit", "10", "--json", "number,title,url",
        ])
        runs = run([
            gh, "run", "list", "--repo", repo, "--limit", "5",
            "--json", "databaseId,displayTitle,status,conclusion,url,workflowName",
        ])
        results.append({
            "repository": repo,
            "state": "READABLE",
            "metadata": metadata,
            "open_pull_requests": json.loads(prs["stdout"] or "[]") if prs["returncode"] == 0 else None,
            "recent_workflows": json.loads(runs["stdout"] or "[]") if runs["returncode"] == 0 else None,
        })
    return {"state": "READ_ONLY_QUERY", "repos": results}


def collect(root: Path) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    rclone = shutil.which("rclone")
    remotes = run([rclone, "listremotes"], timeout=5) if rclone else {
        "available": False, "returncode": None, "stdout": ""
    }
    remote_names = [
        line.strip().rstrip(":") for line in remotes["stdout"].splitlines()
        if line.strip()
    ] if remotes["returncode"] == 0 else None
    return {
        "controller": "ArcaneXus Operations Controller",
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "execution_mode": "READ_ONLY",
        "policy": {
            "automatic": ["local inventory", "loopback port checks", "GitHub read queries when gh is authenticated", "rclone remote-name listing"],
            "approval_required": ["file edits", "deletion", "sync or copy", "merge", "deployment", "permission changes", "external publication", "spending"],
            "secrets_policy": "Do not print credentials, tokens, private keys, or raw authentication output.",
            "action_levels": ACTION_POLICY,
        },
        "workspace": workspace_inventory(root),
        "loopback_services": {str(port): port_state(port) for port in PORTS},
        "rclone": {
            "state": "AVAILABLE" if remotes["returncode"] == 0 else (
                "NOT_INSTALLED" if not remotes["available"] else "UNAVAILABLE"
            ),
            "remote_names": remote_names,
            "note": "Lists configured remote names only; does not contact or synchronize remotes.",
        },
        "github": github_readonly(),
    }


def render(report: dict[str, Any]) -> str:
    workspace = report["workspace"]
    lines = [
        report["controller"],
        f"Generated: {report['generated_at']}",
        f"Mode: {report['execution_mode']}",
        "",
        "WORKSPACE",
        f"  State: {workspace['state']}",
        f"  Path: {workspace['path']}",
        f"  Git checkout: {workspace.get('git_checkout', False)}",
        f"  Master spec present: {workspace.get('master_spec_present', False)}",
        f"  Top-level entries: {workspace.get('top_level_entries', 0)}",
        f"  Backup-named candidates (not confirmed duplicates): {len(workspace.get('backup_named_candidates', []))}",
        "",
        "LOOPBACK SERVICES",
    ]
    lines.extend(f"  127.0.0.1:{port}: {state}" for port, state in report["loopback_services"].items())
    lines += [
        "",
        "RCLONE",
        f"  State: {report['rclone']['state']}",
        f"  Remotes: {', '.join(report['rclone']['remote_names'] or []) or 'none detected'}",
        "",
        "GITHUB",
        f"  Connector via local gh CLI: {report['github']['state']}",
    ]
    for repo in report["github"].get("repos", []):
        lines.append(f"  {repo['repository']}: {repo['state']}")
        if repo.get("state") == "READABLE":
            lines.append(f"    Open PRs: {len(repo.get('open_pull_requests') or [])}")
            lines.append(f"    Recent workflow records: {len(repo.get('recent_workflows') or [])}")
    lines += [
        "",
        "BOUNDARY",
        "  Read-only checks only. No files changed, synced, deleted, merged, or deployed.",
        "  Presence/connectivity is not proof of authorization, integrity, or production readiness.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.environ.get(
        "ARCANEXUS_HOME", str(Path.home() / "ArcaneXus")
    ))
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument(
        "--write-report", action="store_true",
        help="write a timestamped report under ROOT/reports/operations_controller/",
    )
    args = parser.parse_args()
    report = collect(Path(args.root).expanduser().resolve())
    output = json.dumps(report, indent=2, sort_keys=True) if args.json else render(report)
    print(output)
    if args.write_report:
        directory = Path(args.root).expanduser().resolve() / "reports" / "operations_controller"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = directory / f"ops_{stamp}.json"
        with destination.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"\nReport saved: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
