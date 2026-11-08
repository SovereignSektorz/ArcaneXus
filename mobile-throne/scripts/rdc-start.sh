#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
LOG="$HOME/.local/state/arcanexus-throne/rdc.log"
mkdir -p "$(dirname "$LOG")"
if pgrep -f '[d]esktop-commander.*remote|[d]esktop-commander/dist/index.js' >/dev/null 2>&1; then
  echo "RDC already running; leaving existing connection untouched"
  exit 0
fi
command -v npx >/dev/null 2>&1 || { echo "npx missing; install nodejs-lts" >&2; exit 1; }
command -v tmux >/dev/null 2>&1 || { echo "tmux missing" >&2; exit 1; }
termux-wake-lock >/dev/null 2>&1 || true
if tmux has-session -t rdc 2>/dev/null; then
  tmux kill-session -t rdc
fi
tmux new-session -d -s rdc "bash -lc 'npx --yes @wonderwhy-er/desktop-commander@latest remote >> \"$LOG\" 2>&1'"
echo "RDC start requested in tmux session rdc"
