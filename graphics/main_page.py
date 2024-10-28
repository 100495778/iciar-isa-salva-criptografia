import tkinter as tk
import sqlite3 as sql
from . import window

con = sql.connect("DataBase.db")
cur = con.cursor()

frame_mainpage = tk.Frame(master=window.window, width=600, height=600, bg="#b1b7fc")
frame_mainpage.pack_propagate(0)

# Titulo de la app, ahora mas pequeño
lab_title = tk.Label(master=frame_mainpage, text="Forojuegos", fg="#000001", font=('Arial', 12, "bold"), bg="#c5fcfc")
lab_title.pack(side="top", ipadx=260)

# Cargar juegos
cur.execute("SELECT game FROM games")
games = cur.fetchall()

juegos = []
for game in games:
    juegos.append(tk.Button(master=frame_mainpage, text=game, fg="Black", font=('Arial', 10, "bold"), bg="#cdd1fa"))
    juegos[-1].pack(side="top", ipadx=300, pady=10)