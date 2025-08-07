from cryptography.hazmat.primitives.asymmetric import rsa

# 키 생성
def generate_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key

