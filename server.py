import socket
import struct
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = ""
PORT = 5000

# ===== Funciones utilitarias de red =====
def send_raw(sock, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_raw(sock):
    header = recvall(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    return recvall(sock, length)

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# ===== AES =====
def aes_encrypt(aes_key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext

def aes_decrypt(aes_key: bytes, blob: bytes):
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# ===== Manejo de clientes =====
def manejar_cliente(conn, addr, keypair):
    print(f"[+] Conexión desde {addr}")

    # Enviar clave pública
    send_raw(conn, keypair.publickey().export_key())

    # Recibir clave AES cifrada
    enc_session_key = recv_raw(conn)
    if enc_session_key is None:
        conn.close()
        return
    rsa_cipher = PKCS1_OAEP.new(keypair)
    session_key = rsa_cipher.decrypt(enc_session_key)
    print("[SERVIDOR] Clave de sesión AES recibida.")

    # Generar OTP y enviarlo cifrado
    otp = str(get_random_bytes(4).hex())
    send_raw(conn, aes_encrypt(session_key, otp.encode()))

    # Recibir OTP validado
    try:
        client_otp = aes_decrypt(session_key, recv_raw(conn)).decode()
    except:
        conn.close()
        return

    if client_otp == otp:
        send_raw(conn, aes_encrypt(session_key, b"AUTH_OK"))
        print("[SERVIDOR] Cliente autenticado correctamente.")
    else:
        send_raw(conn, aes_encrypt(session_key, b"AUTH_FAIL"))
        conn.close()
        return

    # Loop de mensajes
    while True:
        data = recv_raw(conn)
        if not data:
            break
        try:
            msg = aes_decrypt(session_key, data).decode()
        except:
            break

        if msg.lower() == "exit":
            print("[SERVIDOR] Cliente salió.")
            break

        print(f"[Cliente]: {msg}")
        respuesta = f"Servidor recibió: {msg}"
        send_raw(conn, aes_encrypt(session_key, respuesta.encode()))

    conn.close()

def iniciar_servidor():
    keypair = RSA.generate(2048)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVIDOR] Escuchando en {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        hilo = threading.Thread(target=manejar_cliente, args=(conn, addr, keypair))
        hilo.start()
