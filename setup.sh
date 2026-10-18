#!/usr/bin/env bash
# ============================================================
#  lan-file-share  one-click setup (Linux / macOS)
#  Checks Node.js, installs optional deps, builds the HTTPS
#  certificate, then starts the server.
# ============================================================
set -u
cd "$(dirname "$0")" || exit 1

echo "============================================================"
echo "  LAN File Share - one-click setup"
echo "============================================================"
echo

# ---- 1) Node.js -------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "[ERROR] Node.js not found."
  echo "        Please install Node.js 18 or newer from https://nodejs.org/ then run setup.sh again."
  exit 1
fi
echo "[OK]   Node.js $(node -v)"

# ---- 2) optional dependencies ----------------------------------
if [ -d node_modules/sharp ]; then
  echo "[OK]   dependencies already installed."
else
  echo "[..]   installing optional dependencies: sharp / archiver / webdav-server"
  echo "       this may take a few minutes on first run ..."
  if npm install --no-audit --no-fund; then
    echo "[OK]   dependencies installed."
  else
    echo "[WARN] npm install failed. The server still runs, but these are disabled:"
    echo "       low-res previews, ZIP batch download, WebDAV. Fix it later with: npm install"
  fi
fi

# ---- 3) HTTPS certificate -------------------------------------
if [ -f certs/server.crt ]; then
  echo "[OK]   certificate already exists."
else
  echo "[..]   generating self-signed HTTPS certificate ..."
  if node gen-cert.js; then
    echo "[OK]   certificate generated."
  else
    echo "[WARN] certificate generation failed - openssl is required."
    echo "       Install openssl, then run setup.sh again."
    echo "       You can also generate it manually:  node gen-cert.js"
  fi
fi

# ---- 4) run ----------------------------------------------------
mkdir -p share
echo
echo "============================================================"
echo "  Setup finished. Starting the server ..."
echo "============================================================"
echo
exec node server.js
