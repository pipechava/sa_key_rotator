import subprocess
import pkcs11
import numpy as np
from pkcs11 import KeyType, Mechanism, ObjectClass, Attribute
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key
from OpenSSL import crypto
import pkcs11
import datetime
import cryptography
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from pkcs11 import Attribute
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pyhsm.hsmclient import HsmClient

# Initialize the token
subprocess.run(["softhsm2-util", "--init-token", "--slot", "1883957978", "--label", "MyToken", "--so-pin", "1234", "--pin", "1234"])
subprocess.run(["softhsm2-util", "--show-slots"])

lib_path = '/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so'
lib = pkcs11.lib(lib_path)
token = lib.get_token(token_label="MyToken")

def pyhsm_login():
    # note: the with keyword can be used to reduce login / logout steps
    # what is shown below is the verbose method
    c = HsmClient(pkcs11_lib=lib_path)
    c.open_session(slot=1883957978)
    c.login(pin="1234")
    # c.logout()
    # c.close_session()
    # note: listing slot information does not require a login
    with HsmClient(pkcs11_lib="/usr/lib/vendorp11.so") as c:
        for s in c.get_slot_info():
            print("----------------------------------------")
            print(s.to_string())
    
def pyhsm_create_rsa_key_pair(c):
    with c:
        key_handles = c.create_rsa_key_pair(public_key_label="my_rsa_pub",
                                            private_key_label="my_rsa_pvt",
                                            key_length=2048,
                                            public_exponent=b"\x01\x00\x01",
                                            token=True,
                                            private=True,
                                            modifiable=False,
                                            extractable=False,
                                            sign_verify=True,
                                            encrypt_decrypt=True,
                                            wrap_unwrap=True,
                                            derive=False)
        print("public_handle: " + key_handles[0])
        print("private_handle: " + key_handles[1])
        public_handle = key_handles[0]
        private_handle = key_handles[1]
        
        # Get the RSA public and private keys
        public_key = c.get_public_key(public_handle)
        private_key = c.get_private_key(private_handle)
        
        return public_key, private_key
    


def create_cert(public_key, private_key):
    # Create a new X509 object, representing a certificate
    cert = crypto.X509()

    # Set properties of the certificate
    cert.get_subject().C = "US"  # Country
    cert.get_subject().ST = "State"  # State
    cert.get_subject().L = "City"  # City

    # Serial number, validity of certificate
    cert.set_serial_number(1000)
    # Certificate valid from now
    cert.gmtime_adj_notBefore(0)
    # Certificate valid to 10 years from now
    cert.gmtime_adj_notAfter(10*365*24*60*60)

    # Use the public and private keys to set up and sign the certificate
    cert.set_pubkey(public_key)
    cert.set_issuer(cert.get_subject())
    cert.sign(private_key, 'sha256')

    # Finally, write the certificate to a file
    with open('certificate.pem', 'wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))

    print("Certificate created and written to 'certificate.pem'.")
    

c = pyhsm_login()
public_key, private_key = pyhsm_create_rsa_key_pair(c)
create_cert(public_key, private_key)

    



