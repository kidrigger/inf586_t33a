# based on https://realpython.com/python-sockets/#echo-server

import socket
import subprocess
from myutil import create_rsa_key, crypt_recv, crypt_sendall, get_public_key, rsa_decrypt

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 4567  # Port to listen on (non-privileged ports are > 1023)

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
            while True:
                data = crypt_recv(conn, 2048, symkey)
                if not data:
                    break
                res = subprocess.run(data, shell=True, capture_output=True, check=False, text=True)
                crypt_sendall(conn, res.stdout + res.stderr, symkey)
    
