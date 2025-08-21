from flask import Flask, request, jsonify, send_file, after_this_request, abort
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone
import tempfile
import requests
import os
import io
import zipfile


app = Flask(__name__)

CA_KEY_FILE = "ca_private_key.pem"
CA_CERT_FILE = "ca_cert.pem"

# 1. Create root CA if not exists
def create_ca():
    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    with open(CA_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# 2. Load CA key and certificate
def load_ca():
    with open(CA_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_FILE, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return private_key, cert

# 3. CSR submission endpoint
@app.route('/sign', methods=['POST'])
def sign_csr():
    csr_pem = request.files['csr'].read()

    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError:
        return "Invalid CSR format", 400

    # 1. 서명 유효성 확인
    if not csr.is_signature_valid:
        return "Invalid CSR signature", 400

    # 2. Subject 필드 확인
    required_oids = [NameOID.COMMON_NAME, NameOID.COUNTRY_NAME]
    subject_oids = [attr.oid for attr in csr.subject]
    for oid in required_oids:
        if oid not in subject_oids:
            return f"Missing required subject field: {oid._name}", 400

    # 3. 도메인 필터링 (예: 허용된 도메인만 발급)
    cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
    common_name = cn_attr.value
    if not common_name.endswith(".mycompany.com"):
        return "Only *.mycompany.com domains are allowed", 403

    # 4. 키 사이즈 검사
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            return "Key size too small. Minimum 2048 bits required.", 400

    # 5. 서명 및 발급
    private_key, ca_cert = load_ca()
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM), 200, {'Content-Type': 'application/x-pem-file'}

# 4. CA Certificate download
@app.route('/ca-cert', methods=['GET'])
def get_ca_cert():
    return send_file(CA_CERT_FILE, mimetype='application/x-pem-file')


@app.post("/get_key")
def get_key():
    r = request.get_json(silent=True) or {}
    try:
        country_name = r["country_name"]
        province_name = r["province_name"]
        local_name = r["local_name"]
        org_name = r["org_name"]
        common_name = r["common_name"]
    except KeyError as e:
        return abort(400, f"missing field: {e}")

    safe = secure_filename(common_name) or "client"

    # 1) 개인키 생성
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 운영 시엔 PKCS#8 + 암호화 권장 (BestAvailableEncryption)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1(RSA) - 필요시 PKCS8로 변경 가능
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2) CSR 생성
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, province_name),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, local_name),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # 3) CA 서버에 CSR 제출 → cert PEM 수신
    #    multipart 업로드 형식 (필요시 필드명/엔드포인트 맞춰 조정)
    resp = requests.post(
        "http://localhost:5000/sign",
        files={"csr": ("request.csr", csr_pem, "application/pkcs10")}
    )
    if resp.status_code != 200:
        return abort(502, f"CA sign failed: {resp.status_code}")
    cert_pem = resp.content  # PEM 형식 인증서

    # 4) 메모리에서 ZIP 구성 (개인키 + 인증서)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{safe}.key.pem", key_pem)
        z.writestr(f"{safe}.crt.pem", cert_pem)
        # 필요하면 체인도 추가: z.writestr(f"{safe}-chain.crt.pem", chain_pem)

    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{safe}_key_and_cert.zip"
    )
    
if __name__ == '__main__':
    create_ca()
    app.run(host="0.0.0.0", port=5000)
