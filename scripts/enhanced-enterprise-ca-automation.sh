#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
This legacy wrapper has been retired because Azure VM Run Command can expose
certificate passwords through command parameters and logs.

Use the supported flow instead:
1. Export the certificate with ca-quick-setup.ps1 or ca-simple-setup.ps1 and
   supply -PfxPassword as a SecureString.
2. Set PFX_PASSWORD only in the local process environment.
3. Run scripts/upload-certificates.sh.
EOF
exit 1