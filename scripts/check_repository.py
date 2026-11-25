"""Check the Git publication set without printing secrets or contacting external services."""

import ast
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PARTS = {".local", ".venv", ".codex", "node_modules", "__pycache__"}
RETIRED = {"src/ati_downstream", "experiments/ati-downstream-mas", "experiments/mas-ati"}


def candidates():
    result = set()
    for args in (
        ("ls-files", "-z"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    ):
        result.update(subprocess.check_output(["git", *args], cwd=ROOT).decode().split("\0"))
    return [ROOT / name for name in sorted(result) if name and (ROOT / name).is_file()]


def known_local_secrets():
    """Compare against existing private values; emit neither values nor their hashes."""
    from dotenv import dotenv_values

    found = set()
    for path in (ROOT / ".env",):
        if path.exists():
            for key, value in dotenv_values(path).items():
                if (
                    value
                    and len(value) >= 12
                    and any(word in key.upper() for word in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
                ):
                    found.add(value.encode())
    for path in (ROOT / ".local/state/oauth").glob("*.json"):
        value = json.loads(path.read_text())
        if isinstance(value, dict):
            for key in ("access_token", "refresh_token", "id_token", "client_secret"):
                if isinstance(value.get(key), str) and len(value[key]) >= 12:
                    found.add(value[key].encode())
    return found


def content(path):
    if path.suffix == ".docx":
        with zipfile.ZipFile(path) as archive:
            return b"\n".join(
                archive.read(name)
                for name in archive.namelist()
                if name.endswith((".xml", ".rels"))
            )
    return path.read_bytes()


def main():
    failures = []
    files = candidates()
    secrets = known_local_secrets()
    links = 0
    for path in files:
        name = path.relative_to(ROOT).as_posix()
        if (
            PRIVATE_PARTS.intersection(path.relative_to(ROOT).parts)
            or any(name.startswith(prefix + "/") for prefix in RETIRED)
            or path.name.startswith(".env")
            and path.name != ".env.example"
            or path.suffix in {".sqlite", ".db", ".key", ".pem", ".pyc"}
            or path.suffix == ".pdf"
        ):
            failures.append((name, "private or retired file is in the publication set"))
            continue
        data = content(path)
        if any(secret in data for secret in secrets):
            failures.append((name, "contains an existing private credential"))
        for pattern in (
            rb"gh[pousr]_[A-Za-z0-9]{30,}",
            rb"github_pat_[A-Za-z0-9_]{40,}",
            rb"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}",
            rb"-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----",
        ):
            if re.search(pattern, data):
                failures.append((name, "credential-shaped material requires removal"))
        try:
            if path.suffix == ".py":
                ast.parse(data, filename=name)
            elif path.suffix == ".json":
                json.loads(data)
            elif path.suffix == ".toml" or path.name == "uv.lock":
                tomllib.loads(data.decode())
            elif path.suffix in {".yaml", ".yml"}:
                import yaml

                yaml.safe_load(data)
        except (ValueError, SyntaxError) as error:
            failures.append((name, f"invalid syntax: {type(error).__name__}"))
        if path.suffix != ".md":
            continue
        # Code samples can intentionally contain illustrative Markdown paths.
        text = re.sub(r"```.*?```", "", data.decode(), flags=re.DOTALL)
        for match in re.finditer(r"\]\(([^)]+)\)", text):
            target = match[1].strip().strip("<>").split(' "', 1)[0]
            if urlsplit(target).scheme or target.startswith("#"):
                continue
            local = unquote(target.split("#", 1)[0])
            if local:
                links += 1
                if not (path.parent / local).exists():
                    failures.append((name, f"missing relative link: {local}"))
    print(
        json.dumps(
            {
                "publication_files": len(files),
                "relative_links_checked": links,
                "known_local_credentials_checked": bool(secrets),
                "failures": [{"file": name, "reason": reason} for name, reason in failures],
            },
            indent=2,
        )
    )
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
