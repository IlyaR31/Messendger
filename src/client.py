from rich.console import Console

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from RSAlib import generate_keys, decrypt_data, encrypt_data
from datetime import datetime
import threading
import random
import socket
import struct
import json
import time

console = Console()

RSA_KEY_SIZE = 24 # Чтобы быстро

def key_exchange(sock):
    rsa_open_key, rsa_private_key = generate_keys(RSA_KEY_SIZE)

    send_data(sock, json.dumps(list(rsa_open_key)).encode())

    res_encrypted = json.loads(receive_data(sock).decode())
    res = decrypt_data(res_encrypted, rsa_private_key)

    key = res[:32]
    initialization_vector = res[32:]

    algorithm = algorithms.AES(key)
    mode = modes.CTR(initialization_vector)

    cipher = Cipher(algorithm, mode)
    return cipher

def send_data_encrypted(connection, data, cipher):
    send_data(connection, cipher.encryptor().update(data))

def receive_data_encrypted(connection, cipher):
    return cipher.decryptor().update(receive_data(connection))

def send_string_encrypted(connection, data, cipher):
    send_data(connection, cipher.encryptor().update(data.encode()))

def receive_string_encrypted(connection, cipher):
    return (cipher.decryptor().update(receive_data(connection))).decode()

def send_data(connection, data):
    size = len(data)
    size_bytes = struct.pack("<I", size)
    connection.send(size_bytes)
    connection.send(data)

def receive_data(connection):
    size_bytes = connection.recv(4)
    size = struct.unpack("<I", size_bytes)[0]

    data = b''
    while len(data) < size:
        data += connection.recv(1024)

    return data

def send_string(connection, string):
    send_data(connection, string.encode('utf-8'))

def receive_string(connection):
    return receive_data(connection).decode('utf-8')


def open_connection(server, port, bind_host, nickname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))

    cipher = key_exchange(sock)

    bind_port = random.randint(1024, 65535)
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind((bind_host, bind_port))
    serv.listen(1)

    send_string_encrypted(sock, json.dumps({
        "host": bind_host, "port": bind_port, "nickname": nickname
    }), cipher)

    serv, _ = serv.accept()

    if not receive_string_encrypted(serv, cipher) == "ok":
        raise ConnectionError
    return sock, serv, cipher

def stop(sock):
    send_string_encrypted(sock, json.dumps({"type": "pleasestopimbegging"}), cipher)
    stopped.set()
    sock.shutdown(socket.SHUT_RDWR)
    serv.shutdown(socket.SHUT_RDWR)
    serv.close()
    sock.close()

def receiver(serv):
    while not stopped.is_set():
        try:
            data = receive_string_encrypted(serv, cipher)
        except:
            break
        data = json.loads(data)
        t = datetime.fromtimestamp(data["timestamp"])

        if data["type"] == "message":
            console.print(f"[cyan]{data["username"]}[/cyan]: [bold]{data["message"]}[/bold] [dim]({t.hour}:{t.minute}:{t.second})[/dim]")
        elif data["type"] == "info":
            console.print(f"[cyan]{data["message"]}[/cyan] [dim]({t.hour}:{t.minute}:{t.second})[/dim]")

        console.print("[bold cyan]>> [/]", end="")

def sender(sock):
    while not stopped.is_set():
        send_message(sock, console.input("[bold cyan]>> [/]"))

def send_message(sock, message):
    message = {"message": message, "timestamp": time.time(), "type": "message"}
    send_string_encrypted(sock, json.dumps(message), cipher)


console.print("""[bold cyan] _   _       
| \\_/ | _    
| \\_/ |/o\\\\V7
|_| |_|\\_//n\\
    [/][dim]messenger[/]""")

host = console.input("[bold cyan]Enter host:[/] ")
port = console.input("[bold cyan]Enter port:[/] ")

nickname = console.input("[bold cyan]Enter nickname:[/] ")

sock, serv, cipher = open_connection(port, int(host), "127.0.0.1", nickname)

stopped = threading.Event()

recv = threading.Thread(target=receiver, args=(serv,))
send = threading.Thread(target=sender, args=(sock,))
send.daemon = True
recv.daemon = True
recv.start()
send.start()
try:
    recv.join()
except KeyboardInterrupt:
    stop(sock)

