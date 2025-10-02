import socket                     # módulo para sockets (TCP/IP)
import threading                  # para manejar múltiples clientes concurrentemente con hilos
import struct                     # para empacar/desempacar enteros a bytes (ej. prefijo de longitud)
import os                         # operaciones sobre sistema de archivos (comprobar existencia de archivos)
from Crypto.PublicKey import RSA  # generación/importación/exportación de claves RSA (PEM <-> objeto)
from Crypto.Cipher import PKCS1_OAEP, AES  # RSA-OAEP para cifrado asimétrico, AES para cifrado simétrico
from Crypto.Random import get_random_bytes  # fuente criptográfica de bytes aleatorios

HOST = '192.168.20.14'   # escuchar en todas las interfaces de red disponibles
PORT = 5000        # puerto TCP donde el servidor aceptará conexiones

RSA_KEY_SIZE = 2048   # tamaño de la clave RSA (en bits). 2048 es el mínimo recomendado.
AES_KEY_SIZE = 32     # tamaño en bytes de la clave AES (32 bytes = 256 bits)

# Estructuras para manejar OTP en memoria (ejemplo educativo)
unused_otps = set()     # OTPs generadas y no consumidas
used_otps = set()       # OTPs ya consumidas (marcadas)
lock = threading.Lock() # bloqueo para proteger acceso concurrente a las estructuras de OTP

def generate_rsa_keys():
    """
    Genera un par de claves RSA (privada y pública) en archivos PEM si no existen.
    - Evita regenerar claves si ya están en disco (evita invalidar claves en uso).
    - En producción: proteger el archivo privado, usar HSM/KMS si es posible.
    """
    # Si falta alguna de las dos claves en disco, generamos nuevas
    if not os.path.exists('server_private.pem') or not os.path.exists('server_public.pem'):
        key = RSA.generate(RSA_KEY_SIZE)            # genera el par RSA
        private_pem = key.export_key()              # exporta la clave privada en formato PEM (bytes)
        public_pem = key.publickey().export_key()   # exporta la clave pública en PEM (bytes)
        with open('server_private.pem', 'wb') as f: # escribe la privada en disco (modo binario)
            f.write(private_pem)
        with open('server_public.pem', 'wb') as f:  # escribe la pública en disco (modo binario)
            f.write(public_pem)
        print('RSA keys generadas: server_private.pem, server_public.pem')
    else:
        # Si ya existen, simplemente informamos y no sobreescribimos
        print('RSA keys ya existen. Usando las existentes.')

def load_private_key():
    """
    Carga la clave privada RSA desde el archivo 'server_private.pem' y la devuelve
    como objeto RSA utilizable por PyCryptodome.
    """
    with open('server_private.pem', 'rb') as f:
        return RSA.import_key(f.read())

def send_raw(sock, data: bytes):
    """
    Envía datos por socket con framing: primero 4 bytes (big-endian) indicando la longitud,
    luego los `data` bytes. Esto facilita que el receptor lea exactamente el mensaje completo.
    """
    sock.sendall(struct.pack('!I', len(data)) + data)  # '!I' = entero unsigned 4 bytes en network order

def recv_raw(sock):
    """
    Recibe un mensaje que fue enviado con send_raw:
    1) lee 4 bytes para obtener la longitud
    2) lee exactamente esa cantidad de bytes
    Devuelve None si la conexión se cierra inesperadamente.
    """
    header = recvall(sock, 4)       # leer la cabecera de 4 bytes
    if not header:
        return None                 # conexión cerrada antes de recibir la cabecera
    (length,) = struct.unpack('!I', header)  # desempaquetar la longitud
    return recvall(sock, length)    # leer `length` bytes y devolverlos

def recvall(sock, n):
    """
    Lee exactamente `n` bytes del socket; recv puede devolver menos, por eso iteramos.
    Devuelve None si la conexión se cierra antes de obtener todos los bytes.
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))  # leer los bytes faltantes
        if not packet:
            return None                    # conexión cerrada
        data += packet
    return data

def aes_encrypt(aes_key: bytes, plaintext: bytes):
    """
    Cifra `plaintext` con AES-GCM usando `aes_key`.
    - Genera un nonce/IV seguro de 12 bytes.
    - Devuelve un blob concatenado: nonce(12) || tag(16) || ciphertext.
    IMPORTANTE: no reutilizar nonce con la misma clave.
    """
    nonce = get_random_bytes(12)                   # nonce recomendado de 12 bytes para GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # crear cifrador GCM con nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext) # cifrar y obtener tag de autenticación
    return nonce + tag + ciphertext                # empaquetar los elementos para envío

def aes_decrypt(aes_key: bytes, blob: bytes):
    """
    Descifra un blob en formato nonce(12) || tag(16) || ciphertext usando AES-GCM.
    - Verifica la integridad con el tag; si la verificación falla, se lanza excepción.
    - Devuelve el plaintext descifrado (bytes).
    """
    nonce = blob[:12]          # extraer nonce
    tag = blob[12:28]          # extraer tag (16 bytes)
    ciphertext = blob[28:]     # resto -> ciphertext
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)   # crear cifrador con el mismo nonce
    plaintext = cipher.decrypt_and_verify(ciphertext, tag) # descifrar y verificar tag
    return plaintext

def generate_otp():
    """
    Genera un OTP numérico de 6 dígitos:
    - Se usan 3 bytes aleatorios (24 bits), se toma módulo 1_000_000 para obtener 0..999999,
      y se rellena con ceros a la izquierda si es necesario.
    - Se añade al conjunto `unused_otps` protegido por un lock para manejo concurrente.
    """
    otp = str(int.from_bytes(get_random_bytes(3), 'big') % 1000000).zfill(6)
    with lock:
        unused_otps.add(otp)
    return otp

def validate_and_consume_otp(otp: str):
    """
    Valida si `otp` está en `unused_otps`. Si es válido:
    - lo elimina de unused_otps y lo añade a used_otps (consumido), evitando reuso/replay.
    - toda la operación se hace bajo `lock` para ser atómica.
    Devuelve True si era válido, False si no.
    """
    with lock:
        if otp in unused_otps:
            unused_otps.remove(otp)
            used_otps.add(otp)
            return True
    return False

def handle_client(conn, addr, private_key):
    """
    Maneja la comunicación con un cliente conectado (protocolo completo).
    Flujo:
    1) Enviar la clave pública del servidor (PEM) al cliente.
    2) Recibir la clave AES de sesión cifrada con RSA (OAEP) y descifrarla.
    3) Generar un OTP, cifrarlo con AES y enviarlo al cliente.
    4) Recibir de vuelta el OTP cifrado con AES; descifrar y validar (consumir).
    5) Si OTP válido -> enviar AUTH_OK cifrado y entrar en bucle de mensajes cifrados.
    6) Si en cualquier paso hay fallo, cerrar conexión.
    """
    print(f'Cliente conectado: {addr}')
    try:
        # 1) enviar clave pública al cliente (PEM)
        pub_pem = private_key.publickey().export_key()  # exportar la clave pública en bytes PEM
        send_raw(conn, pub_pem)                         # enviar al cliente

        # 2) recibir clave AES cifrada con RSA (desde el cliente)
        enc_session_key = recv_raw(conn)
        if enc_session_key is None:
            # conexión cerrada antes de enviar la clave AES
            print('Conexión cerrada antes de recibir AES key')
            conn.close()
            return
        rsa_cipher = PKCS1_OAEP.new(private_key)  # crear objeto RSA-OAEP para descifrar
        try:
            session_key = rsa_cipher.decrypt(enc_session_key)  # descifrar la clave AES
        except Exception as e:
            # si falla, puede indicar datos corruptos o ataque; cerramos conexión
            print('Fallo al descifrar AES key con RSA:', e)
            conn.close()
            return

        print('AES key de sesión recibida y descifrada.')

        # 3) generar OTP y enviarlo cifrado con AES al cliente
        otp = generate_otp()
        print(f'OTP generado (temporario): {otp}')       # (solo para ejemplo/troubleshooting; no en producción)
        enc_otp_blob = aes_encrypt(session_key, otp.encode())  # cifrar OTP con AES-GCM
        send_raw(conn, enc_otp_blob)                    # enviar blob al cliente

        # 4) esperar que el cliente devuelva el OTP cifrado con AES
        client_response = recv_raw(conn)
        if client_response is None:
            print('Cliente desconectado antes de enviar OTP')
            conn.close()
            return
        try:
            recovered = aes_decrypt(session_key, client_response).decode()  # descifrar y decodificar a string
        except Exception as e:
            # fallo en la verificación de integridad o en el descifrado
            print('Fallo al descifrar respuesta AES del cliente:', e)
            # enviamos (a modo de ejemplo) una respuesta de fallo en claro; en producción cifrar siempre
            send_raw(conn, b'AUTH_FAIL')
            conn.close()
            return

        # validar y consumir OTP (evita reuso)
        if validate_and_consume_otp(recovered):
            print('OTP validado con éxito por el servidor.')
            send_raw(conn, aes_encrypt(session_key, b'AUTH_OK'))  # confirmar autenticación al cliente (cifrado)
        else:
            print('OTP inválido o ya usado.')
            send_raw(conn, aes_encrypt(session_key, b'AUTH_FAIL'))  # notificar fallo (cifrado)
            conn.close()
            return

        # 5) Bucle principal: recibir mensajes cifrados por AES y responder
        while True:
            enc_msg = recv_raw(conn)           # leer mensaje enmarcado
            if enc_msg is None:
                print('Cliente desconectado')
                break
            try:
                msg = aes_decrypt(session_key, enc_msg).decode()  # descifrar y obtener texto
            except Exception as e:
                # fallo al descifrar o verificación de integridad -> terminar la sesión
                print('Error al descifrar mensaje AES:', e)
                break
            print(f'MENSAJE DE {addr}:', msg)
            if msg.lower() == 'exit':
                # si el cliente pide terminar, salimos limpiamente
                print('Cliente pidió terminar la sesión.')
                break
            # preparar y enviar respuesta cifrada
            reply = f'SERVER RECEIVED: {msg}'.encode()
            send_raw(conn, aes_encrypt(session_key, reply))

    finally:
        # siempre cerrar la conexión y limpiar recursos al finalizar la función
        conn.close()
        print(f'Conexión con {addr} cerrada.')

def start_server():
    """
    Inicializa el servidor:
    - Genera/valida las claves RSA en disco.
    - Carga la clave privada.
    - Crea el socket TCP, lo configura y entra en bucle aceptando conexiones.
    - Cada cliente es atendido en un hilo separado (daemon).
    """
    generate_rsa_keys()                 # crear claves si no existen
    private_key = load_private_key()    # cargar clave privada para uso en descifrado RSA
    print('Iniciando servidor...')
    # crear socket TCP y usar context manager para que se cierre automáticamente
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # permitir reusar dirección (reinicios rápidos)
        s.bind((HOST, PORT))   # enlazar socket a la IP y puerto definidos
        s.listen()             # poner socket en modo escucha
        print(f'Escuchando en {HOST}:{PORT}')
        while True:
            conn, addr = s.accept()  # accept() bloquea hasta que llega una nueva conexión
            # iniciar un hilo para manejar el cliente; daemon=True para que no bloquee el cierre del proceso
            t = threading.Thread(target=handle_client, args=(conn, addr, private_key), daemon=True)
            t.start()

if __name__ == '__main__':
    start_server()  # ejecutar servidor si el script se ejecuta directamente
