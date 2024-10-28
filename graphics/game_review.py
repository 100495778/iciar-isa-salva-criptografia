import tkinter as tk

from . import window

frame_game = tk.Frame(master=window.window, width=600, height=600, bg="#edd4ff")
frame_game.pack_propagate(0)

# Boton de retorno
button_return = tk.Button(master=frame_game, text="Volver", fg="Black", font=('Arial', 10, "bold"), bg="#ffb491")
button_return.pack(side="bottom", ipadx=10, pady=10)

# Boton de enviar review
button_send = tk.Button(master=frame_game, text="Enviar", fg="Black", font=('Arial', 10, "bold"), bg="#ffb491")

# Datos del juego:
lab_game_title = tk.Label(master=frame_game, text="", fg="#000001", font=('Arial', 12, "bold"),
                          bg="#c5fcfc")
lab_game_title.pack(side="top", ipadx=300)
lab_game_info = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"),
                         bg="#c5fcfc")
lab_game_info.pack(side="top", ipadx=50)

# Datos variables
entry_review = tk.Entry(master=frame_game, width=50)
entry_score = tk.Entry(master=frame_game, width=50)
lab_review = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"), bg="#c5fcfc")
lab_score = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"), bg="#c5fcfc")