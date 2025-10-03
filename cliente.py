import socket
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = ""
PORT = 5000

# ===== Funciones de red =====
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

# ===== Cliente API =====
class ClienteSeguro:
    def __init__(self):
        self.sock = None
        self.session_key = None

    def conectar(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        pub_pem = recv_raw(self.sock)
        server_pub = RSA.import_key(pub_pem)

        # Generar AES y enviarlo cifrado
        self.session_key = get_random_bytes(32)
        rsa_cipher = PKCS1_OAEP.new(server_pub)
        send_raw(self.sock, rsa_cipher.encrypt(self.session_key))

        # Recibir OTP
        otp_blob = recv_raw(self.sock)
        otp = aes_decrypt(self.session_key, otp_blob).decode()

        # Enviar OTP de vuelta
        send_raw(self.sock, aes_encrypt(self.session_key, otp.encode()))

        # Confirmación
        status = aes_decrypt(self.session_key, recv_raw(self.sock)).decode()
        if status != "AUTH_OK":
            raise Exception("Autenticación fallida")
        return True

    def enviar_mensaje(self, mensaje: str):
        send_raw(self.sock, aes_encrypt(self.session_key, mensaje.encode()))
        if mensaje.lower() == "exit":
            self.sock.close()
            return "Conexión cerrada"
        resp = recv_raw(self.sock)
        return aes_decrypt(self.session_key, resp).decode()
