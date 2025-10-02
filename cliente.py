import socket                        # módulo para crear sockets TCP/IP
import struct                        # para empacar/desempacar enteros a bytes (ej. longitudes)
from Crypto.PublicKey import RSA     # para importar/usar claves RSA (PEM -> objeto RSA)
from Crypto.Cipher import PKCS1_OAEP, AES  # PKCS1_OAEP: cifrado RSA con padding OAEP; AES: cifrado simétrico
from Crypto.Random import get_random_bytes  # fuente criptográfica de bytes aleatorios

SERVER_HOST = '192.168.20.14'            # dirección IP del servidor al que el cliente se conectará
SERVER_PORT = 5000                   # puerto TCP del servidor


def send_raw(sock, data: bytes):
    # Empaqueta la longitud de `data` como un entero de 4 bytes (big-endian) y envía [len][data].
    # Esto permite al receptor saber exactamente cuántos bytes leer.
    sock.sendall(struct.pack('!I', len(data)) + data)


def recv_raw(sock):
    # Lee primero 4 bytes (cabecera) que indican la longitud del mensaje y luego lee exactamente
    # esa cantidad de bytes usando `recvall`. Devuelve None si la conexión se cierra.
    header = recvall(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('!I', header)  # desempaqueta el entero de 4 bytes a `length`
    return recvall(sock, length)              # devuelve `length` bytes leídos del socket


def recvall(sock, n):
    # Lee exactamente `n` bytes del socket. recv() puede devolver menos bytes que los solicitados,
    # por eso se itera hasta obtenerlos todos o hasta que la conexión se cierre.
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))  # intenta leer los bytes faltantes
        if not packet:
            return None                    # conexión cerrada o error -> devolvemos None
        data += packet
    return data


from Crypto.Cipher import AES as _AES    # importar AES pero nombrarlo _AES para evitar colisiones

def aes_encrypt(aes_key: bytes, plaintext: bytes):
    # Cifra `plaintext` usando AES-GCM con `aes_key`.
    # 1) Genera un nonce (IV) de 12 bytes (recomendado para GCM).
    # 2) Crea el cifrador en modo GCM y cifra + obtiene el tag (autenticación).
    # 3) Devuelve nonce || tag || ciphertext como blob único.
    nonce = get_random_bytes(12)
    cipher = _AES.new(aes_key, _AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_decrypt(aes_key: bytes, blob: bytes):
    # Descifra un blob creado por `aes_encrypt` (nonce(12) | tag(16) | ciphertext).
    # 1) Extrae nonce, tag y ciphertext de `blob`.
    # 2) Crea el cifrador AES-GCM con el nonce y llama a decrypt_and_verify para
    #    descifrar y verificar el tag (integridad). Si la verificación falla, se lanza excepción.
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = _AES.new(aes_key, _AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def main():
    # Bloque principal del cliente: establece la conexión y ejecuta el protocolo de handshake + mensajes.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Crea un socket TCP (IPv4) y lo cierra automáticamente al salir del `with`.
        s.connect((SERVER_HOST, SERVER_PORT))      # Conecta con el servidor en la IP:PUERTO definidos

        pub_pem = recv_raw(s)                      # Recibe la clave pública del servidor en formato PEM
        if pub_pem is None:
            print('No se recibió clave pública. Cerrando.')
            return                                  # Finaliza si no se recibió la clave pública
        server_pub = RSA.import_key(pub_pem)        # Convierte el PEM recibido a un objeto RSA usable
        print('Clave pública del servidor recibida.')

        session_key = get_random_bytes(32)          # Genera una clave AES de sesión (32 bytes = 256 bits)
        rsa_cipher = PKCS1_OAEP.new(server_pub)    # Crea un cifrador RSA-OAEP usando la pública del servidor
        enc_session_key = rsa_cipher.encrypt(session_key)  # Cifra la clave AES con RSA (OAEP)
        send_raw(s, enc_session_key)                # Envía la clave AES cifrada al servidor
        print('AES key de sesión enviada (cifrada con RSA).')

        enc_otp_blob = recv_raw(s)                  # Espera recibir el blob AES que contiene el OTP
        if enc_otp_blob is None:
            print('No se recibió OTP. Cerrando.')
            return                                  # Si no llega, cerramos
        try:
            otp = aes_decrypt(session_key, enc_otp_blob).decode()  # Descifra el blob con la session_key y decodifica a str
        except Exception as e:
            print('Error al descifrar OTP:', e)
            return                                  # Si falla la verificación/tag, abortamos
        print('OTP recibido del servidor:', otp)

        # Envía de vuelta el OTP al servidor cifrado con la misma clave AES (prueba de que el cliente puede descifrar)
        send_raw(s, aes_encrypt(session_key, otp.encode()))

        auth_reply = recv_raw(s)                    # Espera la confirmación (AUTH_OK/AUTH_FAIL) cifrada con AES
        if auth_reply is None:
            print('No se recibió respuesta de autenticación. Cerrando.')
            return
        try:
            status = aes_decrypt(session_key, auth_reply).decode()  # Descifra la confirmación y la convierte a str
        except Exception as e:
            print('Fallo al descifrar confirmación del servidor:', e)
            return
        print('Respuesta de autenticación del servidor:', status)
        if status != 'AUTH_OK':
            print('Autenticación fallida.')
            return                                  # Si no es AUTH_OK, terminamos

        # Si llegamos aquí, la autenticación fue exitosa: entramos en el bucle de mensajes cifrados
        while True:
            msg = input('Mensaje a enviar ("exit" para terminar): ')  # Leer texto desde la consola
            send_raw(s, aes_encrypt(session_key, msg.encode()))      # Cifrar con AES y enviar
            if msg.lower() == 'exit':
                print('Finalizando conexión...')
                break                                            # Si envió 'exit', salimos del loop y cerramos
            enc_resp = recv_raw(s)                                # Esperar respuesta cifrada del servidor
            if enc_resp is None:
                print('Servidor desconectado')
                break
            try:
                resp = aes_decrypt(session_key, enc_resp).decode()  # Descifrar la respuesta y decodificar
            except Exception as e:
                print('Error al descifrar respuesta del servidor:', e)
                break
            print('Servidor >', resp)                              # Mostrar respuesta en consola


if __name__ == '__main__':
    main()   # Ejecuta main() si el script se ejecuta directamente
