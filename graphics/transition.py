import tkinter as tk
from .  import window

frame_transicion = tk.Frame(master=window.window, width=600, height=600, bg="#d3d3d0")
frame_transicion.pack_propagate(0)

lab_loading = tk.Label(master=frame_transicion, text="Cuenta Creada Correctamente", font=("Arial", 25, "bold"), fg="#4CBD49", bg="#D3D3D0")
lab_loading.place(x=50, y=300)