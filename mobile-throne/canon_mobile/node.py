from __future__ import annotations

import os
import platform
from pathlib import Path


def memory_available_mb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def rdc_process_count() -> int:
    count = 0
    proc = Path("/proc")
    if not proc.exists():
        return count
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").lower()
            if b"desktop-commander" in cmd and b"remote" in cmd:
                count += 1
        except OSError:
            continue
    return count


def status() -> dict:
    termux = bool(os.environ.get("TERMUX_VERSION") or os.environ.get("PREFIX", "").endswith("/com.termux/files/usr"))
    uid = os.getuid() if hasattr(os, "getuid") else None
    return {
        "node": "ARCANEXUS_MOBILE_THRONE",
        "designation": "XCOVER_ROOTLESS_VERIFIER",
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "termux": termux,
        "uid": uid,
        "rootless": uid not in (0, None),
        "memory_available_mb": memory_available_mb(),
        "rdc_remote_processes": rdc_process_count(),
        "canon_role": "PUBLIC_VERIFIER_ONLY",
        "private_signing_key_present": False,
        "promotion_authority": False,
        "model_inference_enabled": False,
        "shell_execution_by_node": False,
        "autonomous_device_control": False,
        "network_policy": "REMOTE_COMMANDER_TRANSPORT_ONLY",
    }
