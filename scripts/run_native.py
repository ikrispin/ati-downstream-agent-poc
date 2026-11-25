"""Launch only the pinned unmodified LSCore service using private environment settings."""

import os
import subprocess
from pathlib import Path

from ati_lscore.config import Settings
from ati_lscore.native_config import write_native_config

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "experiments/lscore-core-evaluation/.local/upstream"
REVISION = "7693565545044173814b1c5ad5aa66dd329e8b34"


def main():
    os.chdir(ROOT)
    settings = Settings.load()
    actual = subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"], text=True)
    if actual.strip() != REVISION:
        raise SystemExit("LSCore checkout differs from the recorded pin; no service started")
    local = ROOT / ".local"
    local.mkdir(exist_ok=True, mode=0o700)
    config = write_native_config(settings, local / "lscore.yaml")
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")
    executable = UPSTREAM / ".venv/bin/lightspeed-stack"
    os.execv(
        str(executable),
        [
            str(executable),
            "-c",
            str(config),
            "--synthesized-config-output",
            str(local / "synthesized-ogx.yaml"),
        ],
    )


if __name__ == "__main__":
    main()
