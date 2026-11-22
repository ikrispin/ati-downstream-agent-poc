#!/usr/bin/env bash
# Explicit, reversible trust of this server certificate in Chrome's NSS database.
# Run add only after reviewing/approving the certificate. No system CA is added.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
certificate="$lab_root/.local/state/ui-tls/server.crt"
if command -v certutil >/dev/null; then
  ati_certutil=$(command -v certutil)
else
  ati_certutil="$lab_root/.local/tools/nss/usr/bin/certutil"
fi
if [ ! -x "$ati_certutil" ]; then
  echo 'certutil is required (Fedora package: nss-tools).' >&2
  exit 1
fi
ati_fingerprint=$("$lab_root/.venv/bin/python" -c '
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pathlib import Path
c = x509.load_pem_x509_certificate(Path(sys.argv[1]).read_bytes())
assert not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
print(c.fingerprint(hashes.SHA256()).hex())
' "$certificate")
ati_nickname="ATI downstream local UI ${ati_fingerprint:0:16}"
if [ -n "${ATI_CHROME_NSS_DB:-}" ]; then
  ati_nss_db=$ATI_CHROME_NSS_DB
elif [ -f "$HOME/.pki/nssdb/cert9.db" ]; then
  ati_nss_db="$HOME/.pki/nssdb"
else
  ati_nss_db="$HOME/.local/share/pki/nssdb"
fi
if [ ! -f "$ati_nss_db/cert9.db" ]; then
  echo 'Chrome certificate database not found; open Chrome once before retrying.' >&2
  exit 1
fi
printf 'Certificate SHA-256: %s\nChrome NSS database: %s\n' "$ati_fingerprint" "$ati_nss_db"
case "${1:-status}" in
  add)
    "$ati_certutil" -A -d "sql:$ati_nss_db" -t 'P,,' -n "$ati_nickname" -i "$certificate"
    echo 'Trusted this server certificate only. Reopen Chrome to refresh certificate trust.'
    ;;
  remove)
    "$ati_certutil" -D -d "sql:$ati_nss_db" -n "$ati_nickname"
    echo 'Removed trust for this server certificate.'
    ;;
  status)
    "$ati_certutil" -L -d "sql:$ati_nss_db" -n "$ati_nickname"
    ;;
  *) echo 'Usage: bash scripts/ui-cert-trust.sh add|remove|status' >&2; exit 2 ;;
esac
