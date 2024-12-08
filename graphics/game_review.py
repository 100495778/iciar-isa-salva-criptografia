import tkinter as tk

from . import window

frame_game = tk.Frame(master=window.window, width=600, height=600, bg="#edd4ff")
frame_game.pack_propagate(0)

# Boton de retorno
button_return = tk.Button(master=frame_game, text="Volver", fg="Black", font=('Arial', 10, "bold"), bg="#ffb491")
button_return.pack(side="bottom", ipadx=10, pady=10)

# Datos del juego:
lab_game_title = tk.Label(master=frame_game, text="", fg="#000001", font=('Arial', 12, "bold"), bg="#c5fcfc")
lab_game_title.pack(side="top", ipadx=300)
lab_game_info = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")
lab_game_info.pack(side="top", ipadx=20)

# Botones de ver reviews y mi review
button_mi_review = tk.Button(master=frame_game, text="Mi review", fg="Black", font=('Arial', 10, "bold"), bg="#ffb491")

# No hay review
lab_review_header = tk.Label(master=frame_game, text="Opinion:", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")
entry_review = tk.Entry(master=frame_game, width=50)
# Boton de enviar review
button_send = tk.Button(master=frame_game, text="Enviar", fg="Black", font=('Arial', 10, "bold"), bg="#ffb491")

lab_score_header = tk.Label(master=frame_game, text="Puntuacion:", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")
entry_score = tk.Entry(master=frame_game, width=50)

# Hay review
lab_review = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")
lab_score = tk.Label(master=frame_game, text="", fg="Black", font=('Arial', 10, "bold"), bg="#e8fcfc")