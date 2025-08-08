import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 1. 개인 키 생성
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2. CSR subject 설정
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seoul"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Gangnam"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany Inc."),
    x509.NameAttribute(NameOID.COMMON_NAME, u"client1.mycompany.com"),
])

# 3. CSR 생성
csr = x509.CertificateSigningRequestBuilder().subject_name(
    subject
).sign(key, hashes.SHA256())

# 4. 저장 (옵션)
with open("client_private_key.pem", "wb") as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("client_csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# 5. Flask CA 서버에 제출
files = {'csr': open('client_csr.pem', 'rb')}
response = requests.post('http://localhost:5000/sign', files=files)

# 6. 응답 저장
if response.status_code == 200:
    with open("client_cert.pem", "wb") as f:
        f.write(response.content)
    print("✅ 인증서 발급 완료: client_cert.pem")
else:
    print("❌ 오류 발생:", response.text)
