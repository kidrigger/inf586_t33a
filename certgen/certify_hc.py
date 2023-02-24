import base64
import subprocess
from sys import argv
import json
import os 
dir_path = os.path.dirname(os.path.realpath(__file__))

KEYS = ('id', 'pk', 'ca', 'sig')
ID, PK, CA, SIG = KEYS

def b64_str_to_bytes(strdata: str) -> bytes:
    return base64.b64decode(strdata.encode())

def b64_str_to_str(strdata: str) -> str:
    return b64_str_to_bytes(strdata).decode()

def create_cert_string(id, pubkey, ca_name):
    return f"{id}.{pubkey}.{ca_name}"

def verify_certificate(hostname:str, certfile: str, ca_name: str, ca_pub: str):
    try:
        with open(certfile, 'r') as file_:
            certificate = file_.read()
        cert = json.loads(b64_str_to_str(certificate))
        if any([key_ not in cert for key_ in KEYS]):
            return ''
        if ca_name != cert[CA]:
            return ''
        if hostname != cert[ID]:
            return ''
        cert_str = create_cert_string(cert[ID], cert[PK], cert[CA])
        with open('tempsig.bin', 'wb') as file_:
            file_.write(b64_str_to_bytes(cert[SIG]))
        verif = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', dir_path + '/' + ca_pub, '-signature', 'tempsig.bin'], input=cert_str, text=True, capture_output=True, check=True).stdout
        if 'ok' in verif.lower():
            return cert[PK]
        return ''
    except:
        return ''

if __name__ == '__main__':
    if len(argv) != 3:
        print("Usage: certify <hostname> <certfile>")
        exit(1)
    
    (_, hostname, certfile) = argv
    ca_name = 'root42'
    ca_pubkey = 'ca_public.pem'

    print(verify_certificate(hostname, certfile, ca_name, ca_pubkey))

