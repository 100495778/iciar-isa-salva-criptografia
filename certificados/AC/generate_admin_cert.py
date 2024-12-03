import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization


# Generate our key
root_key = ec.generate_private_key(ec.SECP256R1())

# Write our key to disk for safe keeping
with open("AC_key.pem", "wb") as f:
    f.write(root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(input("Enter password: "), "utf-8")),
    ))

# generate certificate request
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganés"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Forojuegos"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Forojuegos AC"),
])

# Sign our certificate with our private key
root_cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    # Our certificate will be valid for 1 year
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=0),
    critical=True,
).add_extension(
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
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
    critical=False,
).sign(root_key, hashes.SHA256())

# Write our certificate out to disk.

with open("AC_cert.pem", "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))