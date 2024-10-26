# Este archivo servirá para las acciones correspondientes a las reviews de los juegos
import os
import sqlite3 as sql
con = sql.connect("DataBase.db") # Crea/usa la tabla
cur = con.cursor()
from clases import criptografia

class gestionReviews:
    def __init__(self):
        # self.review = []  # creamos una lista vacia donde iran las reviews ?????
        ...

    def crearReview(self, review):
        # este método se encargará ????
        ...

    def encriptarReview(self, review):
        """Este método se encargará de cifrar tanto el texto como el score con una misma clave que se generará
        aquí. Van a ser claves de 256 bits: la opción de clave más larga que ofrece AES"""

        texto = review.texto
        puntuacion = review.puntuacion

        # generamos la clave simétrica con la que encriptaremos ambas cosas
        symm_key = os.urandom(32)

        texto_encriptado = criptografia.encriptado_simetrico(texto, symm_key)
        puntuacion_encriptado = criptografia.encriptado_simetrico(puntuacion, symm_key)

        # nuestro objeto review ahora tiene los datos correspondientes encriptados
        review.texto = texto_encriptado
        review.puntuacion = puntuacion_encriptado

        return review, symm_key


    def encriptar_symm_key(self, symm_key):
        """Este método se encargará de pasar la clave simétrica por el algoritmo de cifrado asimétrico elegido para
        poder luego meterla en la base de datos con el método insertarReviewDB"""
        ...

        #return symm_key_encrypted


    def insertarReviewDB(self, review_encriptada, symm_key_encrypted):
        """Este método meterá la review ya encriptada en la base de datos, en la tabla de reviews; junto con
        la clave simétrica que permitirá desencriptarla. La clave simétrica también estará encriptada de manera
        asimétrica con la clave pública del destinatario"""

        # sacamos los datos del objeto de la review ya encriptada
        usuario = review_encriptada.usuario
        juego = review_encriptada.juego
        texto= review_encriptada.texto
        puntuacion = review_encriptada.puntuacion

        # metemos los datos en la base de datos en la tabla reviews
        con = sql.connect("DataBase.db")  # acceso a la tabla
        cur = con.cursor()

        # insertamos con sqlite3
        cur.execute("INSERT INTO reviews (user, game, review_encrypted, score_encrypted, review_key) VALUES (?,?,?,?,?)", (usuario, juego, texto, puntuacion, symm_key_encrypted))

        # guardamos y terminamos el acceso a la base de datos
        con.commit()
        con.close()









