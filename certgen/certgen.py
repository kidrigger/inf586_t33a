import subprocess
from sys import argv
import json
import base64

def bytes_to_b64_str(bytedata: bytes) -> str:
    return base64.b64encode(bytedata).decode()

def str_to_b64_str(strdata: str) -> str:
    return bytes_to_b64_str(strdata.encode())

def create_cert_string(id, pubkey, ca_name):
    return f"{id}.{pubkey}.{ca_name}"

def sign(id: str, pubkey: str, ca_name: str, privkeyfile: str):
    cert = create_cert_string(id, pubkey, ca_name)
    bytedata = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', privkeyfile], input=cert.encode(), capture_output=True, check=True).stdout
    return bytes_to_b64_str(bytedata)

def create_certificate(id: str, pubkey: str, ca_name:str, privkeyfile: str):
    sig = sign(id, pubkey, ca_name, privkeyfile)
    return str_to_b64_str(json.dumps({'id':id, 'pk':pubkey, 'ca':ca_name, 'sig': sig}))

if __name__ == '__main__':
    if len(argv) != 5:
        print("Usage: certgen <Identity> <public_key_file> <issuer_name> <issuer_private>")
        exit(1)
    
    (_, ident, pubkeyfile, ca_name, ca_privkeyfile) = argv

    with open(pubkeyfile, 'r') as file_:
        pubkey = file_.read()

    print(create_certificate(ident, pubkey, ca_name, ca_privkeyfile))

