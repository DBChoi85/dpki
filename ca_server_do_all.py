from flask import Flask, request, send_file
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile
import os

app = Flask(__name__)

@app.route('/generate_cert', methods=['POST'])
def generate_cert():
    username = request.form.get("username")
    if not username:
        return "Missing username", 400

    # 1. 키쌍 생성
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 2. Subject 정보 구성
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
    ])

    # 3. 인증서 생성 (Self-signed or CA-signed)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject  # self-signed; CA가 있는 경우는 issuer 따로 지정
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    # 4. PFX (.p12) 번들 생성
    pfx_data = serialization.pkcs12.serialize_key_and_certificates(
        name=username.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"securepassword")
    )

    # 5. 임시 파일로 저장 및 전송
    with tempfile.NamedTemporaryFile(delete=False, suffix=".p12") as tmp:
        tmp.write(pfx_data)
        tmp_path = tmp.name

    response = send_file(tmp_path, as_attachment=True, download_name=f"{username}.p12")
    os.unlink(tmp_path)
    return response

if __name__ == '__main__':
    app.run(port=5000, ssl_context='adhoc')  # 임시 HTTPS
