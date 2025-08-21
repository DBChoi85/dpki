import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print(key)