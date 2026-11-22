"""Check the actual development certificate's browser-facing properties."""

import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID

SCRIPT = Path(__file__).parents[1] / "scripts/prepare_ui_certificate.py"


def prepare(directory):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--directory", str(directory)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_certificate_matches_hcc_names_and_reuses_private_key(tmp_path):
    directory = tmp_path / "tls"
    first = prepare(directory)
    assert first.returncode == 0, first.stderr
    cert = x509.load_pem_x509_certificate((directory / "server.crt").read_bytes())
    key_bytes = (directory / "server.key").read_bytes()
    key = load_pem_private_key(key_bytes, password=None)
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "stage.foo.redhat.com" in names.get_values_for_type(x509.DNSName)
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    cert.verify_directly_issued_by(cert)
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert datetime.now(UTC) < cert.not_valid_after_utc <= datetime.now(UTC) + timedelta(days=30)
    assert stat.S_IMODE((directory / "server.key").stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert prepare(directory).returncode == 0
    assert (directory / "server.key").read_bytes() == key_bytes


def test_partial_configuration_preserves_existing_key(tmp_path):
    (tmp_path / "server.key").write_text("preserve this key")
    result = prepare(tmp_path)
    assert result.returncode != 0
    assert (tmp_path / "server.key").read_text() == "preserve this key"
    assert not (tmp_path / "server.crt").exists()
