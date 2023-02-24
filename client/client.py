# based on https://realpython.com/python-sockets/#echo-client

import socket
import os
from sys import argv

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1603  # The port used by the server

def rsa_encrypt(data: str, pubkeyfile: str):
    with open('bufferrsadec.bin', 'w') as file_:
        file_.write(data)
    os.system(f'openssl rsautl -encrypt -pubin -inkey {pubkeyfile} < bufferrsadec.bin > encryptedrsadec.bin')
    with open('encryptedrsadec.bin', 'rb') as file_:
        return file_.read()

def sym_encrypt(data: str, key: str):
    with open('bufferenc.bin', 'w') as file_:
        file_.write(data)
    os.system(f'openssl enc -aes-256-cbc -base64 -pbkdf2 -k {key} > encryptedenc.bin < bufferenc.bin')
    with open('encryptedenc.bin', 'rb') as file_:
        return file_.read()

def store_pub_key(data: bytes, pubkeyfile: str):
    with open(pubkeyfile, 'wb') as file_:
        file_.write(data)

def sym_decrypt(data: bytes, key: str):
    with open('encrypteddec.bin', 'wb') as file_:
        file_.write(data)
    os.system(f'openssl enc -d -aes-256-cbc -base64 -pbkdf2 -k {key} < encrypteddec.bin > bufferdec.bin')
    with open('bufferdec.bin', 'r') as file_:
        return file_.read()

def crypt_sendall(conn: socket.socket, data: str, key: str):
    crypt_data = sym_encrypt(data, key)
    conn.sendall(crypt_data)

def crypt_recv(conn: socket.socket, bufsize:int, key: str):
    crypt_data = conn.recv(bufsize)
    return sym_decrypt(crypt_data, key)

def crypt_sendfile(conn: socket.socket, filename: str, key: str):
    os.system(f'openssl enc -aes-256-cbc -base64 -pbkdf2 -k {key} > {filename}.enc.bin < {filename}')
    with open(f'{filename}.enc.bin', 'rb') as file_:
        conn.sendfile(file_)

if __name__ == '__main__':
    PUBKEYFILE = 'public.pem'
    KEY = 'uninspiredpasskey'
    TO_SEND = argv[1]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected!")
        data = s.recv(1024)
        if not data:
            exit(1)
        store_pub_key(data, PUBKEYFILE)
        s.sendall(rsa_encrypt(KEY, PUBKEYFILE))
        print("Encryption ready!")
        crypt_sendall(s, TO_SEND, KEY)
        print("Sending file")
        crypt_sendfile(s, TO_SEND, KEY)

    print(f"Finished transfer of {TO_SEND}.")