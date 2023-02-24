import base64
import subprocess
from sys import argv
import json

KEYS = ('id', 'pk', 'ca', 'sig')
ID, PK, CA, SIG = KEYS

def b64_str_to_bytes(strdata: str) -> bytes:
    return base64.b64decode(strdata.encode())

def b64_str_to_str(strdata: str) -> str:
    return b64_str_to_bytes(strdata).decode()

def create_cert_string(id, pubkey, ca_name):
    return f"{id}.{pubkey}.{ca_name}"

def verify_certificate(certfile: str, ca_name: str, ca_pub: str):
    try:
        with open(certfile, 'r') as file_:
            certificate = file_.read()
        cert = json.loads(b64_str_to_str(certificate))
        if any([key_ not in cert for key_ in KEYS]):
            return False
        if ca_name != cert[CA]:
            return False
        cert_str = create_cert_string(cert[ID], cert[PK], cert[CA])
        with open('tempsig.bin', 'wb') as file_:
            file_.write(b64_str_to_bytes(cert[SIG]))
        verif = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', ca_pub, '-signature', 'tempsig.bin'], input=cert_str, text=True, capture_output=True, check=True).stdout
        if 'ok' in verif.lower():
            return True
        return False
    except:
        return False

if __name__ == '__main__':
    if len(argv) != 4:
        print("Usage: certify <certfile> <ca_name> <ca_pubkey>")
        exit(1)
    
    (_, certfile, ca_name, ca_pubkey) = argv

    print(verify_certificate(certfile, ca_name, ca_pubkey))

