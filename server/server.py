# based on https://realpython.com/python-sockets/#echo-server

import socket
import os

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 1603  # Port to listen on (non-privileged ports are > 1023)

def create_rsa_key(privatekeyfile: str, pubkeyfile: str):
    os.system(f'openssl genrsa -out {privatekeyfile} 2048')
    os.system(f'openssl rsa -in {privatekeyfile} -pubout -out {pubkeyfile}')

def get_public_key(pubkeyfile: str):
    with open(pubkeyfile, 'rb') as pubkey:
        return pubkey.read()

def rsa_decrypt(data: bytes, privatekeyfile: str):
    with open('encryptedrsadec.bin', 'wb') as file_:
        file_.write(data)
    os.system(f'openssl rsautl -decrypt -inkey {privatekeyfile} < encryptedrsadec.bin > bufferrsadec.bin')
    with open('bufferrsadec.bin', 'r') as file_:
        return file_.read()

def sym_encrypt(data: str, key: str):
    with open('bufferenc.txt', 'w') as file_:
        file_.write(data)
    os.system(f'openssl enc -aes-256-cbc -base64 -pbkdf2 -k {key} > encryptedenc.bin < bufferenc.txt')
    with open('encryptedenc.bin', 'rb') as file_:
        return file_.read()

def sym_decrypt(data: bytes, key: str):
    with open('encrypteddec.bin', 'wb') as file_:
        file_.write(data)
    os.system(f'openssl enc -d -aes-256-cbc -base64 -pbkdf2 -k {key} < encrypteddec.bin > bufferdec.txt')
    with open('bufferdec.txt', 'r') as file_:
        return file_.read()

def crypt_sendall(conn: socket.socket, data: bytes, key: str):
    crypt_data = sym_encrypt(data, key)
    conn.sendall(crypt_data)

def crypt_recv(conn: socket.socket, bufsize:int, key: str):
    crypt_data = conn.recv(bufsize)
    return sym_decrypt(crypt_data, key)

def sym_decrypt_file(filename: str, key: str):
    os.system(f'openssl enc -d -aes-256-cbc -base64 -pbkdf2 -k {key} < {filename}.enc.bin > {filename}')
    

if __name__ == '__main__':
    PUBKEYFILE = 'public.pem'
    PRIVATEKEYFILE = 'private.pem'
    create_rsa_key(PRIVATEKEYFILE, PUBKEYFILE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            conn.sendall(get_public_key(PUBKEYFILE))
            data = conn.recv(2048)
            if not data:
                exit(1)
            symkey = rsa_decrypt(data, PRIVATEKEYFILE)
            print('Encryption ready!')
            filename = crypt_recv(conn, 2048, symkey)
            print(f'Will recv {filename}')
            with open(f"{filename}.enc.bin", 'wb') as file_:
                while True:
                    data = conn.recv(2048)
                    if not data:
                        break
                    print(f"Got {len(data)} bytes")
                    file_.write(data)
            print(f'Decrypting {filename}')
            sym_decrypt_file(filename, symkey)
            print(f'Done')
        
