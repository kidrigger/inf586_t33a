# based on https://realpython.com/python-sockets/#echo-server

import socket
from myutil import get_certificate
from myutil import create_rsa_key, crypt_recv, get_public_key, rsa_decrypt, sym_decrypt
from sys import argv

HOST = argv[1]  # Standard loopback interface address (localhost)
PORT = int(argv[2])  # Port to listen on (non-privileged ports are > 1023)

if __name__ == '__main__':
    PUBKEYFILE = 'public.pem'
    PRIVATEKEYFILE = 'private.pem'
    create_rsa_key(PRIVATEKEYFILE, PUBKEYFILE)
    cert = get_certificate(HOST, PUBKEYFILE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            conn.sendall(cert.encode())
            data = conn.recv(2048)
            if not data:
                exit(1)
            symkey = rsa_decrypt(data, PRIVATEKEYFILE)
            print(symkey)
            print('Encryption ready!')
            filename = crypt_recv(conn, 2048, symkey)
            print(f'Will recv {filename}')
            filedata = bytes()
            while True:
                data = conn.recv(2048)
                if not data:
                    break
                print(f"Got {len(data)} bytes")
                filedata += data
            print(f'Decrypting {filename}')
            data = sym_decrypt(filedata, symkey)
            with open(filename, 'w') as file_:
                file_.write(data)
            print(f'Done')
        
