from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

# 1️⃣ Alice의 키 쌍 생성
alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
alice_public_key = alice_private_key.public_key()

# 2️⃣ Alice의 CSR 생성
alice_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Alice Corp"),
    x509.NameAttribute(NameOID.COMMON_NAME, "alice.example.com"),
])
csr = x509.CertificateSigningRequestBuilder().subject_name(
    alice_name
).sign(alice_private_key, hashes.SHA256())

# 3️⃣ CA의 키와 이름 정의 (실제 운영이라면 이미 존재해야 함)
ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "myca.example.com"),
])

# 4️⃣ CA가 Alice의 CSR에 서명하여 인증서 발급
certificate = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(ca_name)
    .public_key(csr.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
)

# 5️⃣ 인증서 출력 (PEM)
cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
print(cert_pem.decode())

# (선택) 저장
with open("alice_cert.pem", "wb") as f:
    f.write(cert_pem)
with open("alice_key.pem", "wb") as f:
    f.write(alice_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
