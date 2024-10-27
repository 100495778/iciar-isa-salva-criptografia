import tkinter as tk

from . import window

frame_login = tk.Frame(master=window.window, width=600, height=600, bg="#d3d3d5")
frame_login.pack_propagate(0)

# Titulo de la app
lab_title = tk.Label(master=frame_login, text="Forojuegos", fg="#000001", font=('Arial', 20, "bold"), bg="#edd4ff")
lab_title.pack(side="top", pady=60, ipady=15, ipadx=250)

# Usuario
lab_login_name = tk.Label(master=frame_login, text="Usuario:", fg="Black", bg="#d3d3d5")
lab_login_name.pack(side="top") # Flexbox

entry_login_name = tk.Entry(master=frame_login)
entry_login_name.pack(side="top")

# Contraseña
lab_login_password = tk.Label(master=frame_login, text="Contraseña:", fg="Black", bg="#d3d3d5")
lab_login_password.pack(side="top")

entry_login_password = tk.Entry(master=frame_login, show="*")
entry_login_password.pack(side="top")

# Botón de login
login_button = tk.Button(master=frame_login, text="Acceder", width=10, height=2, bg="#4CBD49", fg="Black")
login_button.pack(side="top", pady=20)

# Botón de registro
lab_signup_swap = tk.Label(master=frame_login, text="¿No tienes cuenta?", fg="Black", bg="#d9d3d2")
lab_signup_swap.pack(side="bottom")

signup_button_swap = tk.Button(master=frame_login, text="Crear cuenta", width=10, height=2, bg="#4CBD49", fg="Black")
signup_button_swap.pack(side="bottom", pady=20)

# Mensaje de error
lab_error_login = tk.Label(master=frame_login, text="Usuario o contraseña no válido", fg="Red", bg="#d9d3d2", font=("Arial", 10, "bold"))