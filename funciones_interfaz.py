import tkinter as tk
import sqlite3 as sql
from random import randint

import logging
from cryptography.hazmat.primitives import serialization

from gestionReviews import gestionReviews as gr, gestionReviews
import criptografia as cripto
from clases.reviews import Review
import certificados as cert

# Importación de frames
from graphics.login import *
from graphics.main_page import *
from graphics.signup import *
from graphics.transicion_certificado import frame_certificado_creado
from graphics.transition import *
from graphics.game_review import *
from graphics.solicitud_certificado import *

from graphics.window import window

# Inicialización de base de datos
con = sql.connect("DataBase.db")
cur = con.cursor()

global user_name, user_public_key, user_password, cert_requested

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
	global cert_requested
	# Comprobar la existencia del certificado
	if not cert_requested:
		button_cert_solicitud.pack(side="bottom", ipadx=20, pady=10)
	else:
		button_cert_solicitud.pack_forget()

	frame_mainpage.pack()
	return


def returnto_app(event):
	frame_game.pack_forget()
	frame_mainpage.pack()
	return

def load_cert_solicitud(event):
	frame_mainpage.pack_forget()
	# Limpiar campos
	entry_nombre.delete(0, len(entry_nombre.get()))
	entry_pais.delete(0, len(entry_pais.get()))
	entry_comunidad.delete(0, len(entry_comunidad.get()))
	entry_localidad.delete(0, len(entry_localidad.get()))
	frame_solicitud.pack()

def returnto_app_fromcert(event):
	frame_certificado_creado.pack_forget()
	frame_solicitud.pack_forget()
	global cert_requested
	# Comprobar la existencia del certificado
	if not cert_requested:
		button_cert_solicitud.pack(side="bottom", ipadx=20, pady=10)
	else:
		button_cert_solicitud.pack_forget()
	frame_mainpage.pack()

def send_cert_request(event):
	cert.generate_cert_request(user_name, user_password, entry_nombre.get(),
							   entry_pais.get(), entry_comunidad.get(), entry_localidad.get())
	frame_solicitud.pack_forget()
	frame_certificado_creado.pack()
	global cert_requested
	cert_requested = True
	window.after(2000, returnto_app_fromcert, event)

def delete_mssg(label):
	"""Funcion que se encarga de borrar los mensajes de error"""
	label.place_forget()


def logout(event):
	# Se borran los datos del usuario
	global user_name, user_public_key, user_password
	user_name = ""
	user_public_key = ""
	user_password = ""
	# Se cierra la sesión
	frame_mainpage.pack_forget()

	# Se carga el login
	entry_login_name.delete(0, len(entry_login_name.get()))
	entry_login_password.delete(0, len(entry_login_password.get()))
	load_login()
	return

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
		global user_name, user_public_key, user_password, cert_requested
		user_name = usuario
		user_password = password
		user_public_key = res[0][2]
		cert_requested = cert.request_exists(user_name)
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
		# Se generan los datos necesarios para la base de datos
		password_hash, salt = cripto.derivar_pwd_usuario(password)
		public_key, private_key = cripto.generar_clave_asymm()
		public_key = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		public_key_firma, private_key_firma = cripto.generar_clave_asymm()
		public_key_firma = public_key_firma.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		# Se insertan los datos en la base de datos
		cur.execute("INSERT INTO users VALUES(?, ?, ?, ?, ?)", (name, password_hash, salt, public_key, public_key_firma))
		con.commit()

		# Si ha salido bien, se guarda la clave privada asimetrica en un archivo
		cripto.guardar_clave_asymm(private_key, name, password)

		cripto.guardar_clave_asymm_firma(private_key_firma, name, password)

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


def send_review(review, public_key):
	review.texto = entry_review.get()
	review.puntuacion = entry_score.get()
	gr_obj = gestionReviews()

	# firmamos sobre los datos no encriptados
	priv_key_firma = cripto.leer_private_key(("certificados/" + user_name + "/" + "private_key_firma.pem"), user_password)
	firma_mensaje = gr_obj.firmar_review(review, priv_key_firma)

	#clave privada para el hmac
	priv_key = cripto.leer_hmac_key(("certificados/" + user_name + "/" + "private_key.pem"), user_password)

	# encriptamos los datos y procedemos a lo demás
	review, symm_key = gr_obj.encriptarReview(review)
	symm_key_encrypted = gr_obj.encriptar_symm_key(symm_key, public_key)
	hmac_mensaje = gr_obj.autenticar_review(symm_key_encrypted, priv_key, review, review.usuario + review.juego)
	gr_obj.insertarReviewDB(review, symm_key_encrypted, hmac_mensaje, firma_mensaje)
	frame_game.pack_forget()
	frame_mainpage.pack()


def load_game(event):
	game_name = event.widget.cget("text")
	frame_mainpage.pack_forget()
	entry_review.delete(0, len(entry_review.get()))
	entry_score.delete(0, len(entry_score.get()))
	entry_review.pack_forget()
	entry_score.pack_forget()
	button_send.pack_forget()
	lab_review.pack_forget()
	lab_score.pack_forget()
	lab_review_header.pack_forget()
	lab_score_header.pack_forget()

	button_mi_review.pack(side="top", ipadx=10, pady=10)
	frame_game.pack()

	cur.execute("SELECT * from games where game = ?", (game_name,))
	res = cur.fetchall()

	# Datos del juego
	info = "Publicacion: " + res[0][1] + " | Género: " + res[0][2]
	game_title = res[0][0]
	lab_game_title.config(text=game_title)
	lab_game_info.config(text=info)

	button_mi_review.bind("<Button-1>", lambda event: get_myreview(game_title))

	return


def get_myreview(game_name):
	button_mi_review.pack_forget()

	# Se obtienen la review.
	oper = gestionReviews()
	review = oper.retreiveReviewDB(user_name, game_name, user_password)
	if review == []:
		# Campo de texto para la review:
		lab_review_header.pack(side="top", pady=10)
		entry_review.pack(side="top", pady=20, ipady=50, ipadx=150)
		lab_score_header.pack(side="top", pady=10)
		entry_score.pack(side="top", pady=20, ipady=10, ipadx=50)

		# Botón de enviar review
		button_send.pack(side="top", ipadx=10, pady=10)
		rev_obj = Review(usuario=user_name, juego=game_name, texto="", puntuacion="")
		button_send.bind("<Button-1>", lambda event: send_review(rev_obj, user_public_key))
	else:
		review_text = "Opinion: " + review[0]["review"]
		lab_review.config(text=review_text)
		lab_review.pack(side="top", ipadx=20, pady=20)
		score = "Puntuacion: " + review[0]["score"]
		lab_score.config(text=score)
		lab_score.pack(side="top", ipadx=20, pady=20)

"""Bindeo de botones <-> funciones"""
def bind():
	signup_button_swap.bind("<Button-1>", login_swap_signup)
	login_button_swap.bind("<Button-1>", signup_swap_login)

	login_button.bind("<Button-1>", login)
	signup_button.bind("<Button-1>", signup)

	for button in juegos:
		button.bind("<Button-1>", load_game)

	button_return.bind("<Button-1>", returnto_app)

	button_logout.bind("<Button-1>", logout)

	button_cert_solicitud.bind("<Button-1>", load_cert_solicitud)
	volver_button.bind("<Button-1>", returnto_app_fromcert)
	send_request_button.bind("<Button-1>", send_cert_request)

	return