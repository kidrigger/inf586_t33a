# based on https://realpython.com/python-sockets/#echo-client

import socket
from myutil import crypt_recv, crypt_sendall, rsa_encrypt, store_pub_key

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 4567  # The port used by the server

if __name__ == '__main__':
    PUBKEYFILE = 'public.pem'
    KEY = 'uninspiredpasskey'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected!")
        data = s.recv(1024)
        if not data:
            exit(1)
        store_pub_key(data, PUBKEYFILE)
        s.sendall(rsa_encrypt(KEY, PUBKEYFILE))
        print("Encryption ready!")
        while True:
            cmd = ""
            try:
                cmd = input("$> ")
            except EOFError:
                break
            if cmd in ("exit", "quit"):
                break
            crypt_sendall(s, cmd, KEY)
            print(crypt_recv(s, 2048, KEY))

    print(f"Shell exit.")