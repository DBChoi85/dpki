from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

# 키 생성
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 이름 설정
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"example.com")
])

# 인증서 빌더
cert_builder = x509.CertificateBuilder(
).subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.now(timezone.utc)
).not_valid_after(
    datetime.now(timezone.utc) + timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(u"example.com"),
        x509.DNSName(u"www.example.com"),
    ]),
    critical=False
)

# 서명
cert = cert_builder.sign(private_key=key, algorithm=hashes.SHA256())

# 출력
print(cert.public_bytes(serialization.Encoding.PEM).decode())

print("Subject:", cert.subject.rfc4514_string())
print("Issuer:", cert.issuer.rfc4514_string())
print("Serial Number:", cert.serial_number)
print("Valid From:", cert.not_valid_before_utc)
print("Valid To:", cert.not_valid_after_utc)
print("Public Key Type:", cert.public_key().__class__.__name__)
print("Signature Algorithm:", cert.signature_hash_algorithm.name)
print("Public key", cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())