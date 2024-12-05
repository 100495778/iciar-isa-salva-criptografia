import tkinter as tk
from . import window

frame_solicitud = tk.Frame(master=window.window, width=600, height=600, bg="#b1b7fc")
frame_solicitud.pack_propagate(0)

# Titulo de la app
lab_title = tk.Label(master=frame_solicitud, text="Forojuegos", fg="#000001", font=('Arial', 12, "bold"), bg="#c5fcfc")
lab_title.pack(side="top", ipadx=260)

# Solicitud de certificado - titulo
lab_solicitud_cert = tk.Label(master=frame_solicitud, text="Solicitud de Certificado", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")
lab_solicitud_cert.pack(side="top", ipadx=20)

# Nombre completo
lab_nombre = tk.Label(master=frame_solicitud, text="Nombre Completo:", fg="Black", bg="#edd4ff")
lab_nombre.pack(side="top", pady=10)

entry_nombre = tk.Entry(master=frame_solicitud)
entry_nombre.pack(side="top", pady=5)

# Pais de residencia
lab_pais = tk.Label(master=frame_solicitud, text="Pais de residencia", fg="Black", bg="#edd4ff")
lab_pais.pack(side="top", pady=5)

entry_pais = tk.Entry(master=frame_solicitud)
entry_pais.pack(side="top", pady=5)

# Comunidad/Estado
lab_comunidad = tk.Label(master=frame_solicitud, text="Comunidad o Estado", fg="Black", bg="#edd4ff")
lab_comunidad.pack(side="top", pady=5)

entry_comunidad = tk.Entry(master=frame_solicitud)
entry_comunidad.pack(side="top", pady=5)

# Comunidad/Estado
lab_localidad = tk.Label(master=frame_solicitud, text="Localidad", fg="Black", bg="#edd4ff")
lab_localidad.pack(side="top", pady=5)

entry_localidad = tk.Entry(master=frame_solicitud)
entry_localidad.pack(side="top", pady=5)


# Botón de volver
volver_button = tk.Button(master=frame_solicitud, text="Volver", width=10, height=2, font=('Arial', 10, "bold"), bg="#ffb491", fg="Black")
volver_button.pack(side="bottom", pady=10)

# Boton de enviar solicitud
send_request_button = tk.Button(master=frame_solicitud, text="Enviar solicitud", width=10, height=2, font=('Arial', 10, "bold"), bg="#4CBD49", fg="Black")
send_request_button.pack(side="bottom", pady=20, ipadx=10)

