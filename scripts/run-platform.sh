#!/usr/bin/env bash
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
export MONGODB_IP=127.0.0.1 MONGODB_PORT=27118 MONGO_DB=ati_downstream_lab
export REDIS_IP=127.0.0.1 REDIS_PORT=6381
export TEMPORAL_IP=127.0.0.1 TEMPORAL_PORT=7333 TEMPORAL_NAMESPACE=default
export ADMIN_ALLOWED_USERS='["dev"]' IDENTITY_PROVIDER_MODE=dev
export SHARED_STORAGE="$lab_root/.local/shared"
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
mkdir -p "$SHARED_STORAGE" "$lab_root/.local/logs"
case "${1:-}" in
  api)
    printf '%s\n' "$$" > "$lab_root/.local/mas-api.pid"
    cd "$lab_root/.local/platform/mas"
    exec .venv/bin/mas api serve --host 127.0.0.1 --port 8111 --workers 1 --threads 4
    ;;
  worker)
    # The pinned MAS seed uses insert rather than upsert; start API first to
    # avoid simultaneous first-start seeding of the settings document.
    for attempt in {1..30}; do
      if curl --fail --silent http://127.0.0.1:8111/api/health/ > /dev/null; then break; fi
      sleep 1
    done
    curl --fail --silent http://127.0.0.1:8111/api/health/ > /dev/null
    printf '%s\n' "$$" > "$lab_root/.local/mas-worker.pid"
    cd "$lab_root/.local/platform/mas"
    exec .venv/bin/mas temporal-worker --threads 4
    ;;
  ui)
    export PATH="$lab_root/.local/tools/node-v22.23.5-linux-x64/bin:$PATH"
    # HCC's development image is public; avoid unrelated, stale registry logins.
    public_registry_auth="$lab_root/.local/state/public-registry-auth.json"
    mkdir -p "$lab_root/.local/state"
    if [ ! -f "$public_registry_auth" ]; then
      (umask 077; printf '%s\n' '{"auths":{}}' > "$public_registry_auth")
    fi
    export REGISTRY_AUTH_FILE="$public_registry_auth"
    "$lab_root/.venv/bin/python" "$lab_root/scripts/prepare_ui_certificate.py"
    cd "$lab_root/.local/platform/ui"
    export MAS_BACKEND_URL=http://127.0.0.1:8111
    export FEC_CONFIG_PATH="$PWD/fec.config.js" FEC_ROOT_DIR="$PWD"
    export CLOUDOT_ENV=stage FEC_CHROME_HOST=stage.foo.redhat.com FEC_CHROME_PORT=9998
    exec npm start -- --clouddot-env stage --webpack-config "$lab_root/scripts/ui-webpack.cjs"
    ;;
  *) echo 'Usage: bash scripts/run-platform.sh api|worker|ui' >&2; exit 2 ;;
esac
