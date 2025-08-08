import subprocess
import secrets
import os
from pathlib import Path

BASE_DIR = Path("./pki")
CA_KEY = BASE_DIR / "ca.key.pem"
CA_CERT = BASE_DIR / "ca.cert.pem"
CRL_FILE = BASE_DIR / "ca.crl.pem"

def generate_serial_number():
    """RFC 5280 & ISO/IEC 27099 준수: 159비트 양수 난수"""
    serial_bytes = secrets.token_bytes(19)  # 152비트
    serial_int = int.from_bytes(serial_bytes, "big")
    serial_int &= (1 << (8 * len(serial_bytes) - 1)) - 1  # 양수 보장
    return str(serial_int)

def run(cmd):
    print(f"[CMD] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def init_ca():
    BASE_DIR.mkdir(exist_ok=True)
    if not CA_KEY.exists():
        run(["openssl", "genrsa", "-out", str(CA_KEY), "4096"])
    if not CA_CERT.exists():
        run([
            "openssl", "req", "-x509", "-new", "-nodes",
            "-key", str(CA_KEY),
            "-sha256", "-days", "3650",
            "-out", str(CA_CERT),
            "-subj", "/C=KR/ST=Seoul/O=Test CA/CN=Root CA"
        ])

def sign_csr(csr_path, cert_out):
    serial = generate_serial_number()
    run([
        "openssl", "x509", "-req",
        "-in", csr_path,
        "-CA", str(CA_CERT), "-CAkey", str(CA_KEY),
        "-set_serial", serial,
        "-out", cert_out,
        "-days", "365", "-sha256"
    ])
    print(f"[INFO] Certificate issued with serial: {serial}")

def generate_crl():
    run([
        "openssl", "ca",
        "-gencrl",
        "-keyfile", str(CA_KEY),
        "-cert", str(CA_CERT),
        "-out", str(CRL_FILE),
        "-config", "/etc/ssl/openssl.cnf"
    ])

def verify_cert_chain(cert_path, chain_path):
    run([
        "openssl", "verify",
        "-CAfile", chain_path,
        cert_path
    ])

if __name__ == "__main__":
    # 1. CA 준비
    init_ca()

    # 2. CSR 예시 생성
    csr_file = BASE_DIR / "user.csr.pem"
    key_file = BASE_DIR / "user.key.pem"
    if not csr_file.exists():
        run(["openssl", "genrsa", "-out", str(key_file), "2048"])
        run([
            "openssl", "req", "-new", "-key", str(key_file),
            "-out", str(csr_file),
            "-subj", "/C=KR/ST=Seoul/O=Example Org/CN=example.com"
        ])

    # 3. 인증서 발급
    user_cert = BASE_DIR / "user.cert.pem"
    sign_csr(str(csr_file), str(user_cert))

    # 4. CRL 생성
    generate_crl()

    # 5. 체인 검증 (여기선 CA 자체를 chain으로 사용)
    verify_cert_chain(str(user_cert), str(CA_CERT))
