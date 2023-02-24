import subprocess
from sys import argv
import json
import base64
import os 
dir_path = os.path.dirname(os.path.realpath(__file__))

def bytes_to_b64_str(bytedata: bytes) -> str:
    return base64.b64encode(bytedata).decode()

def str_to_b64_str(strdata: str) -> str:
    return bytes_to_b64_str(strdata.encode())

def create_cert_string(id, pubkey, ca_name):
    return f"{id}.{pubkey}.{ca_name}"

def sign(id: str, pubkey: str, ca_name: str, privkeyfile: str):
    cert = create_cert_string(id, pubkey, ca_name)
    bytedata = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', dir_path + '/' + privkeyfile], input=cert.encode(), capture_output=True, check=True).stdout
    return bytes_to_b64_str(bytedata)

def create_certificate(id: str, pubkey: str, ca_name:str, privkeyfile: str):
    sig = sign(id, pubkey, ca_name, privkeyfile)
    return str_to_b64_str(json.dumps({'id':id, 'pk':pubkey, 'ca':ca_name, 'sig': sig}))

if __name__ == '__main__':
    if len(argv) != 3:
        print("Usage: certgen <Identity> <public_key_file>")
        exit(1)
    
    (_, ident, pubkeyfile) = argv
    ca_name = 'root42'
    ca_privkeyfile = 'ca_private.pem'

    with open(pubkeyfile, 'r') as file_:
        pubkey = file_.read()

    print(create_certificate(ident, pubkey, ca_name, ca_privkeyfile))

