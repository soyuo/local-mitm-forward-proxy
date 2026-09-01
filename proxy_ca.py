from __future__ import annotations

import argparse
import atexit
import ipaddress
import json
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


APP_NAME = "User Directed Development Local MITM Proxy"
STATE_DIR = Path.home() / ".udd-mitm-proxy"
CA_KEY_PATH = STATE_DIR / "ca.key.pem"
CA_CERT_PATH = STATE_DIR / "ca.cert.pem"
STATE_PATH = STATE_DIR / "state.json"
CERT_CACHE_DIR = STATE_DIR / "certs"


@dataclass(frozen=True)
class CaState:
    subject_cn: str
    thumbprint: str
    cert_path: str
    key_path: str
    created_at: str


def _run_certutil(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["certutil", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _ensure_admin_store_access() -> None:
    probe = _run_certutil(["-user", "-store", "Root"])
    if probe.returncode != 0:
        raise RuntimeError(
            "certutil is not available or the current user certificate store cannot be read."
        )


def _write_state(state: CaState) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state.__dict__, indent=2), encoding="utf-8")


def _read_state() -> CaState | None:
    if not STATE_PATH.exists():
        return None
    data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return CaState(**data)


def _delete_state() -> None:
    if STATE_PATH.exists():
        STATE_PATH.unlink()


def _load_or_create_ca() -> CaState:
    existing = _read_state()
    if existing and CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        return existing

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, APP_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Development"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    state = CaState(
        subject_cn=APP_NAME,
        thumbprint=cert.fingerprint(hashes.SHA1()).hex().upper(),
        cert_path=str(CA_CERT_PATH),
        key_path=str(CA_KEY_PATH),
        created_at=now.isoformat(),
    )
    _write_state(state)
    return state


def ensure_ca_material() -> CaState:
    return _load_or_create_ca()


def ensure_leaf_certificate(hostname: str) -> tuple[Path, Path]:
    ensure_ca_material()
    safe_name = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in hostname)
    cert_path = CERT_CACHE_DIR / f"{safe_name}.cert.pem"
    key_path = CERT_CACHE_DIR / f"{safe_name}.key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    CERT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Development"),
        ]
    )
    try:
        san_name = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san_name = x509.DNSName(hostname)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san_name]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def install_ca() -> CaState:
    _ensure_admin_store_access()
    cleanup_stale_ca()
    state = _load_or_create_ca()
    result = _run_certutil(["-user", "-addstore", "Root", state.cert_path])
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return state


def remove_ca(state: CaState | None = None, keep_files: bool = False) -> None:
    state = state or _read_state()
    if state:
        _run_certutil(["-user", "-delstore", "Root", state.thumbprint])

    if not keep_files:
        for path in (CA_CERT_PATH, CA_KEY_PATH):
            if path.exists():
                path.unlink()
        if CERT_CACHE_DIR.exists():
            for path in CERT_CACHE_DIR.glob("*.pem"):
                path.unlink()
        _delete_state()


def cleanup_stale_ca() -> None:
    state = _read_state()
    if state:
        remove_ca(state, keep_files=False)


def register_shutdown_cleanup() -> None:
    def cleanup(*_: object) -> None:
        remove_ca()

    atexit.register(cleanup)
    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            signal.signal(sig, lambda signum, frame: (cleanup(), sys.exit(128 + signum)))


def run_until_stopped() -> None:
    state = install_ca()
    register_shutdown_cleanup()
    print(f"Installed local proxy CA in CurrentUser Root: {state.thumbprint}")
    print("Press Ctrl+C to remove it and exit.")
    _wait_forever()


def _wait_forever() -> None:
    while True:
        time.sleep(3600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the local MITM proxy root CA.")
    parser.add_argument(
        "command",
        choices=("install", "cleanup", "run"),
        help="install registers the CA, cleanup removes it, run installs and removes on shutdown.",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "install":
            state = install_ca()
            print(state.thumbprint)
        elif args.command == "cleanup":
            cleanup_stale_ca()
        elif args.command == "run":
            run_until_stopped()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
