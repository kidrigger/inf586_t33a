"""My util file"""

import socket
import subprocess

def create_rsa_key(privatekeyfile: str, pubkeyfile: str):
    import os
    os.system(f'openssl genrsa -out {privatekeyfile} 2048')
    os.system(f'openssl rsa -in {privatekeyfile} -pubout -out {pubkeyfile}')

def rsa_encrypt(data: str, pubkeyfile: str) -> bytes:
    return subprocess.run(['openssl', 'rsautl', '-encrypt', '-pubin', '-inkey', pubkeyfile], input=data.encode(), capture_output=True, check=True).stdout

def rsa_decrypt(data: bytes, privatekeyfile: str) -> str:
    return subprocess.run(['openssl', 'rsautl', '-decrypt', '-inkey', privatekeyfile], input=data, capture_output=True, check=True).stdout.decode()


def sym_encrypt(data: str, key: str) -> bytes:
    return subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-base64', '-pbkdf2', '-k', key], input=data.encode(), capture_output=True, check=True).stdout

def sym_decrypt(data: bytes, key: str):
    return subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-base64', '-pbkdf2', '-k', key], input=data, capture_output=True, check=True).stdout.decode()

def crypt_sendall(conn: socket.socket, data: str, key: str):
    crypt_data = sym_encrypt(data, key)
    conn.sendall(crypt_data)

def crypt_recv(conn: socket.socket, bufsize:int, key: str):
    crypt_data = conn.recv(bufsize)
    if not crypt_data:
        return
    return sym_decrypt(crypt_data, key)

def crypt_sendfile(conn: socket.socket, filename: str, key: str):
    with open(filename, 'r') as file_:
        crypt_sendall(conn, file_.read(), key)

def get_public_key(pubkeyfile: str):
    with open(pubkeyfile, 'rb') as pubkey:
        return pubkey.read()
    
def store_pub_key(data: bytes, pubkeyfile: str):
    with open(pubkeyfile, 'wb') as file_:
        file_.write(data)

def get_certificate(id: str, pubkeyfile: str):
    return subprocess.run(['python3', '../certgen/certgen_hc.py', id, pubkeyfile], capture_output=True, check=True, text=True).stdout.strip()

def store_certificate(cert: str, certificatefile: str):
    with open(certificatefile, 'w') as file_:
        file_.write(cert)

def verify_certificate(certfile: str, id: str) -> str:
    pubkey = subprocess.run(['python3', '../certgen/certify_hc.py', id, certfile], capture_output=True, check=True, text=True).stdout
    if not pubkey:
        return None
    return pubkey
