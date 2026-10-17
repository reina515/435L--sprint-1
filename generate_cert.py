"""
Optional HTTPS (Lab 2 item 11: "Use HTTPS for network communication").

    python generate_cert.py      # creates certs/cert.pem and certs/key.pem (self-signed, localhost)
    then set USE_HTTPS=true in .env and restart the services.

Services then listen on https://127.0.0.1:<port> and verify each other's certificate.
In Postman: Settings -> General -> turn OFF "SSL certificate verification"
(the certificate is self-signed), and use https:// in the base URLs.
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(ROOT, "certs")


def main():
    os.makedirs(CERT_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EECE 435L Sprint 1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(os.path.join(CERT_DIR, "key.pem"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(os.path.join(CERT_DIR, "cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(os.path.join(CERT_DIR, "key.pem"), 0o600)
    except OSError:
        pass
    print("Created certs/cert.pem and certs/key.pem - now set USE_HTTPS=true in .env")


if __name__ == "__main__":
    main()
