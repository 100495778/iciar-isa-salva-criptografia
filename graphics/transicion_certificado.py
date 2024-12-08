import tkinter as tk
from .  import window

frame_certificado_creado = tk.Frame(master=window.window, width=600, height=600, bg="#d3d3d0")
frame_certificado_creado.pack_propagate(0)

lab_loading = tk.Label(master=frame_certificado_creado, text="Certificado Digital Solicitado", font=("Arial", 25, "bold"), fg="#4CBD49", bg="#D3D3D0")
lab_loading.place(x=50, y=300)