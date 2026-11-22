"""Create a hostname-correct local UI certificate without changing browser trust."""

import argparse
import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NAMES = ["localhost"] + [
    f"{environment}.foo.redhat.com"
    for environment in ("stage", "prod", "qa", "ci", "ephemeral")
]


def prepare(directory: Path) -> x509.Certificate:
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    key_path, cert_path = directory / "server.key", directory / "server.crt"
    if key_path.exists() or cert_path.exists():
        if not (key_path.is_file() and cert_path.is_file()):
            raise ValueError("Incomplete certificate files; inspect them before regenerating")
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if not set(NAMES).issubset(names.get_values_for_type(x509.DNSName)):
            raise ValueError("Existing certificate does not cover the development hostnames")
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("Existing certificate and private key do not match")
        if cert.not_valid_after_utc <= datetime.now(UTC) + timedelta(days=1):
            raise ValueError(
                "Certificate expires soon; remove its browser trust before replacing it"
            )
        key_path.chmod(0o600)
        return cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stage.foo.redhat.com")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in NAMES]
                + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    for path, data in (
        (
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
        (cert_path, cert.public_bytes(serialization.Encoding.PEM)),
    ):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return cert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ".local/state/ui-tls",
    )
    args = parser.parse_args()
    cert = prepare(args.directory)
    print(f"UI certificate: {args.directory / 'server.crt'}")
    print(f"SHA-256: {cert.fingerprint(hashes.SHA256()).hex()}")
    print(f"Expires: {cert.not_valid_after_utc.isoformat()}")
    print("Browser trust has not been changed.")


if __name__ == "__main__":
    main()
