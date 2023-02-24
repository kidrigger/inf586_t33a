# based on https://realpython.com/python-sockets/#echo-client

import socket
from sys import argv
from myutil import crypt_sendall, crypt_sendfile, rsa_encrypt, store_certificate, store_pub_key, verify_certificate

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1603  # The port used by the server

if __name__ == '__main__':
    PUBKEYFILE = 'public.pem'
    CERTIFICATEFILE = 'cert1.cert'
    KEY = 'uninspiredpasskey'
    TO_SEND = argv[1]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected!")
        data = s.recv(2048)
        if not data:
            exit(1)
        store_certificate(data.decode(), CERTIFICATEFILE)
        pubkey = verify_certificate(CERTIFICATEFILE, 'basicserv')
        if not pubkey or pubkey.strip() == '':
            exit(1)
        store_pub_key(pubkey.encode(), PUBKEYFILE)
        s.sendall(rsa_encrypt(KEY, PUBKEYFILE))
        print("Encryption ready!")
        crypt_sendall(s, TO_SEND, KEY)
        print("Sending file")
        crypt_sendfile(s, TO_SEND, KEY)

    print(f"Finished transfer of {TO_SEND}.")