from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 키 생성
def generate_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pr_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    return pr_key

if __name__ == "__main__":
    print(generate_key())

    

