#!/usr/bin/env bash
#
# Build a standalone macOS executable for the Salesforce MFA audit and
# ad-hoc sign it so it will run locally (and on Apple Silicon, where a
# signature is mandatory).
#
# Usage:
#   ./build.sh
#
# Optional overrides (environment variables):
#   APP_NAME      Output binary name        (default: salesforce-mfa-audit)
#   ENTRY         Entry-point script        (default: audit_mfa.py)
#   TARGET_ARCH   PyInstaller --target-arch (e.g. universal2; default: native)
#
# After this runs you no longer call `pyinstaller` directly -- just run
# `./build.sh`. The signed binary is written to dist/$APP_NAME.

set -euo pipefail

APP_NAME="${APP_NAME:-salesforce-mfa-audit}"
ENTRY="${ENTRY:-audit_mfa.py}"
TARGET_ARCH="${TARGET_ARCH:-}"

cd "$(dirname "$0")"

if [[ ! -f "$ENTRY" ]]; then
  echo "error: entry script '$ENTRY' not found in $(pwd)" >&2
  exit 1
fi

# Resolve a PyInstaller invocation (prefer the module form so it uses the
# same interpreter as python3).
if python3 -c "import PyInstaller" >/dev/null 2>&1; then
  PYINSTALLER=(python3 -m PyInstaller)
elif command -v pyinstaller >/dev/null 2>&1; then
  PYINSTALLER=(pyinstaller)
else
  echo "error: PyInstaller is not installed." >&2
  echo "       Install it with: python3 -m pip install pyinstaller" >&2
  exit 1
fi

echo "==> Building $APP_NAME from $ENTRY"

PYI_ARGS=(--clean --onefile --console --name "$APP_NAME")
if [[ -n "$TARGET_ARCH" ]]; then
  PYI_ARGS+=(--target-arch "$TARGET_ARCH")
fi

"${PYINSTALLER[@]}" "${PYI_ARGS[@]}" "$ENTRY"

BINARY="dist/$APP_NAME"
if [[ ! -f "$BINARY" ]]; then
  echo "error: expected build output '$BINARY' was not produced" >&2
  exit 1
fi

echo "==> Ad-hoc signing $BINARY"
# The "-" identity is an ad-hoc signature (no Developer ID). Sign as the last
# step; any later modification invalidates the signature.
codesign --force --sign - --timestamp=none "$BINARY"
codesign --verify --verbose "$BINARY"

echo
echo "==> Done: $BINARY"
echo
echo "Run it locally:"
echo "    $BINARY"
echo
echo "If you copy it to another Mac and Gatekeeper blocks it, clear quarantine"
echo "on that machine (once):"
echo "    xattr -dr com.apple.quarantine /path/to/$APP_NAME"
echo "    chmod +x /path/to/$APP_NAME"
echo
echo "Reminder: the Salesforce CLI (sf) must be installed and on PATH on the"
echo "machine that runs this binary -- it is not bundled."
