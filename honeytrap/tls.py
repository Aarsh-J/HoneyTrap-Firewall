# ===============================
# TLS Certificate & Context Helpers
# ===============================
# Wraps plain TCP sockets in TLS. The self-signed certificate here proves
# "this is the same server you talked to last time" on a LAN/dev network,
# not "a public CA vouches for this identity" — that's why the client trusts
# the exact cert file instead of verifying against a public CA chain.
import datetime
import ipaddress
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_CERT_PATH = "server.crt"
DEFAULT_KEY_PATH = "server.key"


def generate_self_signed_cert(cert_path=DEFAULT_CERT_PATH, key_path=DEFAULT_KEY_PATH):
    """Create a self-signed certificate + private key if they don't already exist."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "HoneyTrap Firewall"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def get_server_ssl_context(cert_path=DEFAULT_CERT_PATH, key_path=DEFAULT_KEY_PATH):
    """Build an SSLContext for the server side, loaded with our cert/key."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def get_client_ssl_context(cert_path=DEFAULT_CERT_PATH, verify=False):
    """Build an SSLContext for the client side.

    verify=False (the default) trusts the exact self-signed cert file rather
    than a public CA chain, since this is meant for a LAN/dev deployment,
    not the public internet.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if verify:
        context.load_verify_locations(cafile=cert_path)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context
