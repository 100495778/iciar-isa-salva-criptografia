import tkinter as tk

from . import window

frame_signup = tk.Frame(master=window.window, width=600, height=600, bg="#edd4ff")
frame_signup.pack_propagate(0)

# Titulo de la app
lab_title = tk.Label(master=frame_signup, text="Forojuegos", fg="#000001", font=('Arial', 20, "bold"), bg="#d3d3d5")
lab_title.pack(side="top", pady=60, ipady=15, ipadx=250)

# Usuario
lab_signup_name = tk.Label(master=frame_signup, text="Usuario:", fg="Black", bg="#edd4ff")
lab_signup_name.pack(side="top")

entry_signup_name = tk.Entry(master=frame_signup)
entry_signup_name.pack(side="top")

# Contraseña
lab_signup_password = tk.Label(master=frame_signup, text="Contraseña:", fg="Black", bg="#edd4ff")
lab_signup_password.pack(side="top")

entry_signup_password = tk.Entry(master=frame_signup, show="*")
entry_signup_password.pack(side="top")

# Repetir contraseña
lab_signup_password_repeat = tk.Label(master=frame_signup, text="Repetir contraseña:", fg="Black", bg="#edd4ff")
lab_signup_password_repeat.pack(side="top")

entry_signup_password_repeat = tk.Entry(master=frame_signup, show="*")
entry_signup_password_repeat.pack(side="top")

# Botón de registro
signup_button = tk.Button(master=frame_signup, text="Crear cuenta", width=10, height=2, bg="#4CBD49", fg="Black")
signup_button.pack(side="top", pady=20)

# Botón de login
lab_return_login = tk.Label(master=frame_signup, text="¿Ya tienes cuenta?", fg="Black", bg="#edd4ff")
lab_return_login.pack(side="bottom")

login_button_swap = tk.Button(master=frame_signup, text="Acceder", width=10, height=2, bg="#4CBD49", fg="Black")
login_button_swap.pack(side="bottom", pady=20)

# Mensaje de error
lab_error_name = tk.Label(master=frame_signup, text="Usuario no válido", fg="Red", bg="#edd4ff", font=("Arial", 10, "bold"))
lab_error_name_len = tk.Label(master=frame_signup, text="Introduzca un usuario", fg="Red", bg="#edd4ff", font=("Arial", 10, "bold"))
lab_error_password = tk.Label(master=frame_signup, text="Las contraseñas no coinciden", fg="Red", bg="#edd4ff", font=("Arial", 10, "bold"))
lab_error_password_len = tk.Label(master=frame_signup, text="La contraseña ha de tener al menos 8 caracteres", fg="Red", bg="#edd4ff", font=("Arial", 10, "bold"))
