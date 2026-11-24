#!/usr/bin/env bash
# Reproduce the native LSCore source snapshot and both isolated environments.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
evaluation_root="$lab_root/experiments/lscore-core-evaluation"
upstream_root="$evaluation_root/.local/upstream"
lscore_revision=7693565545044173814b1c5ad5aa66dd329e8b34

mkdir -p "$evaluation_root/.local"
chmod 700 "$evaluation_root/.local"
if [ ! -d "$upstream_root/.git" ]; then
  git clone https://github.com/lightspeed-core/lightspeed-stack.git "$upstream_root"
  git -C "$upstream_root" checkout --detach "$lscore_revision"
fi
if [ "$(git -C "$upstream_root" rev-parse HEAD)" != "$lscore_revision" ]; then
  echo 'Existing LSCore checkout differs from the recorded pin; leave it untouched and select a clean workspace.' >&2
  exit 1
fi
git -C "$upstream_root" submodule update --init --recursive

cd "$lab_root"
uvx --from uv==0.13.9 uv sync --frozen --extra test --python 3.12.16
cd "$upstream_root"
uvx --from uv==0.13.9 uv sync --frozen --group dev --group ogxlibdev --python 3.12.16
printf '%s\n' 'Native LSCore and ATI domain tools installed. Configure .env before starting them.'
