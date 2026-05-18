from rich.console import Console
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from RSAlib import encrypt_data
import threading
import secrets
import socket
import struct
import json
import time

console = Console()

def key_exchange(sock):
    rsa_open_key = tuple(json.loads(receive_data(sock).decode()))

    key = secrets.token_bytes(32)
    initialization_vector = secrets.token_bytes(16)
    res = key + initialization_vector

    res_encrypted = json.dumps(encrypt_data(res, rsa_open_key)).encode()

    send_data(sock, res_encrypted)

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

def send_all_except(data, id):
    for connection_id in connections:
        if connection_id != id:
            send_string_encrypted(socks[connection_id]["send"], data, socks[connection_id]["cipher"])
    history.append(data)

def disconnect(id):
    console.print(f"[magenta]{nicknames[id]} left[/]")
    send_all_except(json.dumps({"message": f"{nicknames[id]} отключился!", "timestamp": time.time(), "type": "info"}), id)
    connections.remove(id)
    del nicknames[id]
    socks[id]["send"].close()
    socks[id]["receive"].close()
    del socks[id]

def process_connection(id):
    while True:
        try:
            data = json.loads(receive_string_encrypted(socks[id]["receive"], socks[id]["cipher"]))
        except:
            break
        if data["type"] == "pleasestopimbegging":
            disconnect(id)
            break

        data["username"] = nicknames[id]
        data = json.dumps(data)
        send_all_except(data, id)

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = console.input("[bold cyan]Enter host:[/] ")
port = console.input("[bold cyan]Enter port:[/] ")
serv.bind((host, port))
serv.listen(1)

history = []

connections = []
nicknames = {}
socks = {}

def open_connection(sock_receive):
    id = 0
    while True:
        if id not in connections:
            break
        id += 1

    connections.append(id)

    cipher = key_exchange(sock_receive)

    info = json.loads(receive_string_encrypted(sock_receive, cipher))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((info["host"], info["port"]))

    nicknames[id] = info["nickname"]

    socks[id] = {"receive": sock_receive, "send": sock, "cipher": cipher}
    send_string_encrypted(sock, "ok", cipher)
    console.print(f"[magenta]Connection successful from {info["nickname"]}[/] [dim]id = {id}[/]")
    for message in history:
        send_string_encrypted(socks[id]["send"], message, socks[id]["cipher"])
    return id

console.print("""[bold magenta] _   _       
| \\_/ | _    
| \\_/ |/o\\\\V7
|_| |_|\\_//n\\
       [/][dim]server[/]""")

while True:
    try:
        conn, addr = serv.accept()
        console.print(f"[magenta]New connection from {addr[0]}:{addr[1]}[/]")
    except KeyboardInterrupt:
        serv.close()
        break

    id = open_connection(conn)
    thread = threading.Thread(target=process_connection, args=(id, ))
    thread.start()
    send_all_except(json.dumps({"message": f"{nicknames[id]} подключился!", "timestamp": time.time(), "type": "info"}), id)