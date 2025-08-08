from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, CRLReason
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import secrets

# 1) CA 개인키/인증서 로드
with open("ca_key.pem", "rb") as f:
    ca_key = load_pem_private_key(f.read(), password=None)

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# 2) CRL 빌더 기본 필드
now = datetime.now(timezone.utc)
crl_builder = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(ca_cert.subject)
    .last_update(now)                         # thisUpdate
    .next_update(now + timedelta(days=7))     # nextUpdate: 배포주기 맞춰 잡기
)

# 3) 권장 확장: CRL Number, AKI
# - CRL Number는 단조 증가 값. 예시로 파일/DB에서 읽어오거나, 여기선 123처럼 하드코딩.
crl_number = x509.CRLNumber(123)
crl_builder = crl_builder.add_extension(crl_number, critical=False)

# AKI: CA cert의 SKI를 가져다가 AKI로 실어주는 패턴이 일반적
try:
    ski = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
    aki = x509.AuthorityKeyIdentifier(key_identifier=ski.digest,
                                      authority_cert_issuer=None,
                                      authority_cert_serial_number=None)
    crl_builder = crl_builder.add_extension(aki, critical=False)
except x509.ExtensionNotFound:
    pass  # CA cert에 SKI가 없으면 생략

# 4) 폐지할 인증서들 추가 (없으면 빈 CRL 생성도 가능)
#    각 엔트리에 serial, revocation_date, reason 등을 기록
def add_revoked(serial: int, revoked_at: datetime, reason: x509.ReasonFlags | None):
    revoked = x509.RevokedCertificateBuilder() \
        .serial_number(serial) \
        .revocation_date(revoked_at) \
        .add_extension(x509.CRLReason(reason), critical=False) if reason else \
        x509.RevokedCertificateBuilder() \
            .serial_number(serial) \
            .revocation_date(revoked_at)
    return revoked.build()



def generate_serial_number():
    """
    RFC 5280 및 ISO/IEC 27099 준수:
    - 159비트 난수 (20바이트 미만, 양의 정수)
    - 최상위 비트는 0으로 설정하여 음수 방지
    """
    # 19바이트(152비트) 난수 생성 후 int 변환
    serial_bytes = secrets.token_bytes(19)
    serial_int = int.from_bytes(serial_bytes, byteorder="big")
    # MSB가 1이면 음수로 해석될 수 있으므로, 비트 마스크로 보정
    serial_int &= (1 << (8 * len(serial_bytes) - 1)) - 1
    return serial_int

# 예시로 두 개 추가
crl_builder = crl_builder.add_revoked_certificate(
    add_revoked(serial=0x01ABCDEF, revoked_at=now - timedelta(days=1), reason=x509.ReasonFlags.key_compromise)
)
crl_builder = crl_builder.add_revoked_certificate(
    add_revoked(serial=0x02ABCDEF, revoked_at=now - timedelta(hours=2), reason=x509.ReasonFlags.cessation_of_operation)
)

# 5) CRL 서명
#    해시알고리즘은 CA 키/정책에 맞춰 선택(SHA256 많이 씀)
crl = crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

# 6) 저장 (PEM / DER)
with open("ca.crl.pem", "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.PEM))

with open("ca.crl.der", "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.DER))
