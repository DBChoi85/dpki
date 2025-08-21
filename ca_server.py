from flask import Flask, request, jsonify, send_file, after_this_request
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone
import tempfile
import requests
import os

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


@app.route('/get_key', methods=['POST'])
def get_key():
    r = request.get_json()
    username = r["common_name"]
    print(username)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(encoding=serialization.Encoding.PEM, 
                            format=serialization.PrivateFormat.TraditionalOpenSSL, 
                            encryption_algorithm=serialization.NoEncryption())
    
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    country_name = r["country_name"]
    province_name = r['province_name']
    local_name = r['local_name']
    org_name = r['org_name']
    common_name = r['common_name']
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, local_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())

    try:
        tmp.write(pem)
        tmp_path = tmp.name
    finally:
        tmp.close()

    @after_this_request
    def remove_file(response):
        try:
            os.remove(tmp_path)
            csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
            requests.post('http://localhost:5000/sign', files=csr_bytes)
        except Exception as e:
            app.logger.warning(f"temp delete failed: {e}")
        return response

    return send_file(
        tmp_path,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{username}.pem"
    )

    
if __name__ == '__main__':
    create_ca()
    app.run(host="0.0.0.0", port=5000)
