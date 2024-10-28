import tkinter as tk
import sqlite3 as sql
from random import randint

import criptografia as cripto

# Importación de frames
from graphics.login import *
from graphics.main_page import *
from graphics.signup import *
from graphics.window import window
from graphics.transition import frame_transicion, lab_loading

# Inicialización de base de datos
con = sql.connect("DataBase.db")
cur = con.cursor()

"""Funciones auxiliares"""
def load_signup():
	frame_signup.pack()
	# Limpiar campos
	entry_login_name.delete(0, len(entry_login_name.get()))
	entry_login_password.delete(0, len(entry_login_password.get()))
	return


def load_login():
	frame_login.pack()
	# Limpiar campos
	entry_signup_name.delete(0, len(entry_signup_name.get()))
	entry_signup_password.delete(0, len(entry_signup_password.get()))
	entry_signup_password_repeat.delete(0, len(entry_signup_password_repeat.get()))
	return


def login_swap_signup(event):
	# Cambio de frames
	frame_login.pack_forget()
	load_signup()
	return


def signup_swap_login(event):
	# Cambio de frames
	frame_signup.pack_forget()
	load_login()
	return


def account_created():
	# Cambio de frames
	frame_transicion.pack_forget()
	load_login()
	return

def load_app():
	frame_login.pack_forget()
	frame_mainpage.pack()
	return


def delete_mssg(label):
	"""Funcion que se encarga de borrar los mensajes de error"""
	label.place_forget()


"""Funciones con queries a la base de datos"""
def login(event):
	# Se obtienen los datos aportados por el usuario
	usuario = entry_login_name.get()
	password = entry_login_password.get()

	# Busqueda de usuario en la base de datos
	cur.execute("SELECT password_hash, salt, public_key from users where user = ?", (usuario,))
	res = cur.fetchall()

	if res == []:
		# Si no se encuentra al usuario, se imprime un mensaje de error
		lab_error_login.place(x=200, y=350)
		window.after(2000, delete_mssg, lab_error_login)
		return

	# Se comparan los hashes de contraseñas
	if cripto.verificar_pwd_usuario(res[0][0], password, res[0][1]):
		# Si las contraseñas coinciden, se carga la aplicación
		global user_name, user_public_key
		user_name = usuario
		user_public_key = res[0][2]
		load_app()
		return
	else:
		# Si las contraseñas no coinciden, se imprime un mensaje de error
		lab_error_login.place(x=200, y=350)
		window.after(2000, delete_mssg, lab_error_login)
		return


def signup(event):
	name = entry_signup_name.get()
	# Se comprueba que el nombre de usuario no esté vacío
	if len(name) == 0:
		lab_error_name_len.place(x=230, y=400)
		window.after(2000, delete_mssg, lab_error_name_len)
		return

	# Se comprueba que la contraseña no sea menor de 8 caracteres
	password = entry_signup_password.get()
	if len(password) < 8:
		lab_error_password_len.place(x=150, y=400)
		window.after(2000, delete_mssg, lab_error_password_len)
		return

	password_repeat = entry_signup_password_repeat.get()
	# Se comprueba que las contraseñas coincidan
	if password != password_repeat:
		lab_error_password.place(x=200, y=400)
		window.after(2000, delete_mssg, lab_error_password)
		return

	# Se trata de insertar el nuevo usuario en la base de datos
	try:
		password_hash, salt = cripto.derivar_pwd_usuario(password)
		public_key, private_key = cripto.generar_claves_asymm()

		# Se insertan los datos en la base de datos
		cur.execute("INSERT INTO users VALUES(?, ?, ?, ?)", (name, password_hash, salt, public_key))
		con.commit()

		# Si ha salido bien, se guarda la clave privada asimetrica en un archivo
		cripto.guardar_clave_asymm(private_key)

		# Se muestra un mensaje de éxito y se carga el login para que el usuario inicie sesion
		frame_signup.pack_forget()
		frame_transicion.pack()
		window.after(1000, account_created)
		return

	except sql.IntegrityError:
		# Si da error, el usuario ya existe. Se muestra un mensaje de error
		delete_mssg(lab_error_password)
		delete_mssg(lab_error_password_len)
		lab_error_name.place(x=190, y=400)
		window.after(3500, delete_mssg, lab_error_name)
		return


def load_game(event):
	pass





"""Bindeo de botones <-> funciones"""

signup_button_swap.bind("<Button-1>", login_swap_signup)
login_button_swap.bind("<Button-1>", signup_swap_login)

login_button.bind("<Button-1>", login)
signup_button.bind("<Button-1>", signup)
