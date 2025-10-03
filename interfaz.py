import tkinter as tk
from tkinter import messagebox
from cliente import ClienteSeguro

def interfaz_principal():
    cliente = ClienteSeguro()
    try:
        cliente.conectar()
        messagebox.showinfo("Conexión", "✅ Autenticado con el servidor")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo conectar: {e}")
        return

    ventana = tk.Tk()
    ventana.title("Cliente Seguro")
    ventana.geometry("400x300")

    tk.Label(ventana, text="Enviar mensaje al servidor", font=("Arial", 14, "bold")).pack(pady=10)

    entrada = tk.Entry(ventana, width=40)
    entrada.pack(pady=10)

    def enviar():
        msg = entrada.get()
        if msg.strip() == "":
            return
        try:
            resp = cliente.enviar_mensaje(msg)
            messagebox.showinfo("Respuesta", resp)
            if msg.lower() == "exit":
                ventana.quit()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(ventana, text="Enviar", command=enviar).pack(pady=10)
    tk.Button(ventana, text="Salir", command=ventana.quit).pack(pady=10)

    ventana.mainloop()
