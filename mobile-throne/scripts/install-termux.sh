#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -n "${TERMUX_VERSION:-}" ]] || { echo "DENY: run this installer inside Termux" >&2; exit 2; }
python -c 'import cryptography' 2>/dev/null || { echo "Installing Python cryptography dependency"; python -m pip install --user -r "$ROOT/requirements.txt"; }
DEST="$HOME/.local/share/arcanexus-mobile-throne"
mkdir -p "$DEST" "$PREFIX/bin" "$HOME/.termux/boot"
rm -rf "$DEST/canon_mobile" "$DEST/tests" "$DEST/scripts"
cp -R "$ROOT/canon_mobile" "$DEST/"
cp -R "$ROOT/tests" "$DEST/"
cp -R "$ROOT/scripts" "$DEST/"
cat > "$PREFIX/bin/ax-throne" <<'WRAPPER'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
export PYTHONPATH="$HOME/.local/share/arcanexus-mobile-throne${PYTHONPATH:+:$PYTHONPATH}"
exec python -m canon_mobile.cli "$@"
WRAPPER
chmod 700 "$PREFIX/bin/ax-throne" "$DEST/scripts/rdc-start.sh"
BOOT="$HOME/.termux/boot/05_arcanexus_rdc.sh"
if [[ -e "$BOOT" ]]; then
  cp -p "$BOOT" "$BOOT.bak.$(date -u +%Y%m%dT%H%M%SZ)"
fi
cat > "$BOOT" <<'BOOTFILE'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
termux-wake-lock >/dev/null 2>&1 || true
exec "$HOME/.local/share/arcanexus-mobile-throne/scripts/rdc-start.sh"
BOOTFILE
chmod 700 "$BOOT"
echo "Installed ax-throne at $PREFIX/bin/ax-throne"
echo "Installed Termux:Boot hook at $BOOT"
ax-throne status
