#!/usr/bin/env bash
# Set up the optional MAS development environment in this checkout.
set -euo pipefail
: "${MAS_REPOSITORY_URL:?Set MAS_REPOSITORY_URL to an accessible MAS Git repository}"
: "${MAS_UI_REPOSITORY_URL:?Set MAS_UI_REPOSITORY_URL to an accessible MAS UI Git repository}"
lab_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$lab_root"
mkdir -p .local/platform .local/logs .local/verification
chmod 700 .local
bash scripts/setup-runtimes.sh
python_executable="$lab_root/.local/tools/python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12"
export PATH="$lab_root/.local/tools/node-v22.23.5-linux-x64/bin:$PATH"
uv sync --locked --python "$python_executable" --extra test --extra ui

checkout() {
  local target=$1 remote=$2 revision=$3
  if [ ! -d "$target/.git" ]; then
    git clone --no-checkout "$remote" "$target"
    git -C "$target" checkout --detach "$revision"
  elif [ "$(git -C "$target" rev-parse HEAD)" != "$revision" ]; then
    echo "Unexpected revision in $target; preserve local changes and inspect before proceeding." >&2
    exit 1
  fi
}
checkout .local/platform/mas "$MAS_REPOSITORY_URL" \
  d5a93001da2836177252d5719f7de57f698edcee
checkout .local/platform/ui "$MAS_UI_REPOSITORY_URL" \
  986a54ad6ec1cfc47cfc7028253f5ac8bb6b7c64

if git -C .local/platform/mas apply --check "$lab_root/patches/mas-a2a-outcomes.patch"; then
  git -C .local/platform/mas apply "$lab_root/patches/mas-a2a-outcomes.patch"
else
  git -C .local/platform/mas apply --reverse --check "$lab_root/patches/mas-a2a-outcomes.patch"
fi
if git -C .local/platform/mas apply --check "$lab_root/patches/mas-openai-optional-tools.patch"; then
  git -C .local/platform/mas apply "$lab_root/patches/mas-openai-optional-tools.patch"
else
  git -C .local/platform/mas apply --reverse --check \
    "$lab_root/patches/mas-openai-optional-tools.patch"
fi
(cd .local/platform/mas && uv sync --frozen --python "$python_executable" --extra all --no-dev)
(cd .local/platform/ui && npm ci --no-audit --no-fund)
echo 'Bootstrap finished. Configure .env, then start infrastructure and services as in README.md.'
