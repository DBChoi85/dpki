from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime

def verify_certificate(cert_pem_path, ca_cert_pem_path):
    # 1. 인증서와 CA 인증서 로드
    with open(cert_pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_cert_pem_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # 2. 유효기간 검증
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise Exception("❌ 인증서 유효기간이 지났거나 아직 시작되지 않음.")

    # 3. 발급자(issuer) 확인
    if cert.issuer != ca_cert.subject:
        raise Exception("❌ 인증서 발급자가 CA 인증서와 일치하지 않음.")

    # 4. 서명(Signature) 검증
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),   # RSA의 경우
            cert.signature_hash_algorithm
        )
    except Exception as e:
        raise Exception("❌ 인증서 서명 검증 실패.") from e

    print("✅ 인증서 검증 성공 - 발급 CA:", cert.issuer)

# 사용 예시
verify_certificate("client_cert.pem", "ca_cert.pem")
