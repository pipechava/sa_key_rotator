from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import subprocess
import os

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def write_keys_to_files(private_key, public_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pem)

def create_self_signed_cert(private_key_path, public_key_path):
    cert_file = "self_signed.crt"
    if os.path.exists(cert_file):
        os.remove(cert_file)
        
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-key", private_key_path,
        "-out", cert_file, "-days", "365"
    ], check=True, text=True, input="\n"*7)
    
    return cert_file

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    write_keys_to_files(private_key, public_key)
    create_self_signed_cert("private_key.pem", "public_key.pem")
