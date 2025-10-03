import threading
from server import servidor
import interfaz

if __name__ == "__main__":
    # Iniciar servidor en un hilo
    hilo_servidor = threading.Thread(target=servidor.iniciar_servidor, daemon=True)
    hilo_servidor.start()

    # Iniciar interfaz gráfica
    interfaz.interfaz_principal()
