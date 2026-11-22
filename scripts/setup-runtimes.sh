#!/usr/bin/env bash
# Install this experiment's runtimes privately; leave system Python/Node intact.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$lab_root"
if [ "$(uname -sm)" != 'Linux x86_64' ]; then
  echo 'The pinned runtime downloads support Linux x86_64. Select official builds for this machine first.' >&2
  exit 1
fi
mkdir -p .local/tools/downloads
chmod 700 .local
python_executable="$lab_root/.local/tools/python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12"
if [ ! -x "$python_executable" ]; then
  # This uv release includes the Python 3.12.16 download metadata.
  uvx --from uv==0.13.9 uv python install 3.12.16 --install-dir .local/tools/python --no-bin
fi
node_directory="$lab_root/.local/tools/node-v22.23.5-linux-x64"
if [ ! -x "$node_directory/bin/node" ]; then
  archive=node-v22.23.5-linux-x64.tar.xz
  curl --fail --silent --show-error --location \
    "https://nodejs.org/dist/v22.23.5/$archive" -o ".local/tools/downloads/$archive"
  # SHA-256 from the official Node.js v22.23.5 SHASUMS256.txt, checked 2026-11-18.
  printf '%s  %s\n' \
    cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8 \
    ".local/tools/downloads/$archive" | sha256sum --check
  tar -xJf ".local/tools/downloads/$archive" -C .local/tools
fi
"$python_executable" --version
"$node_directory/bin/node" --version
