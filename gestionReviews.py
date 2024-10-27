# Este archivo servirá para las acciones correspondientes a las reviews de los juegos
import os
import sqlite3 as sql
import criptografia


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

        texto_encriptado = criptografia.cifrado_simetrico(texto, symm_key)
        puntuacion_encriptado = criptografia.cifrado_simetrico(puntuacion, symm_key)

        # nuestro objeto review ahora tiene los datos correspondientes encriptados
        review.texto = texto_encriptado
        review.puntuacion = puntuacion_encriptado

        return review, symm_key


    def encriptar_symm_key(self, symm_key, public_key):
        """Este método se encargará de pasar la clave simétrica por el algoritmo de cifrado asimétrico elegido para
        poder luego meterla en la base de datos con el método insertarReviewDB"""

        symm_key_encrypted = criptografia.cifrado_asimetrico(symm_key, public_key)

        return symm_key_encrypted


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


    # AHORA LO RELACIONADO CON OBTENER DATOS DE LA BASE DE DATOS Y DEESENCRIPTARLOS -------------------------------
    def retreiveReviewDB(self, usuario):
        """Este método hace coge la información de la base de datos correspondiente al usuario que la quiera obtener
        :return devuelve lista de diccionarios que contienen información sobre (usuario, juego, review, score y clave simetrica)
                Habrá "x" diccionarios correspondientes a las "x" reviews que corresponden al usuario "usuario".
        """

        # accedemos a la base de datos
        con = sql.connect("DataBase.db")  # acceso a la tabla
        cur = con.cursor()

        # seleccionamos los datos de las reviews correspondientes al usuario que las requiere
        cur.execute("SELECT user, game, review_encrypted, score_encrypted, review_key FROM reviews WHERE user = ?", (usuario,))

        retrieved_data = cur.fetchall()     # esto nos devuelve una lista de tuplas con todos los datos obtenidos sobre ese usuario

        """ La lista retreived_data tiene:
                tupla[0] = usuario
                tupla[1] = juegos
                tupla[2] = reviews encriptadas
                tupla[3] = scorings encriptadas
                tupla[4] = claves simétricas encriptadas
            Entonces, sabiendo esto vamos a: desencriptar cada elemento de esas 3 columnas con la clave pública 
            perteneciente al usuario y meterlo todo en una lista de diccionarios para poder acceder más fácil 
        """

        # desciframos la clave simétrica usando la privada del elemento ?????????????????????????????????????????????
        # ??????????????????????????????????????????????????? NO SÉ CÓMO ACCEDER AL .PEM ??????????????????????????
        # ????????????????????????????????????????????????????????????????????????????????????????????????????????
        # COGER LA CLAVE PRIVADA PORFI !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! HACERLO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡

        clave_privada = ...

        # Esta lista será una lista de diccionarios. Cada diccionario contendrá información sobre una review en concreto,
        # por lo que esta lista tendrá x diccionarios, siendo x el número de reviews asociadas a ese usuario
        datos_utiles = []

        # ahora desciframos las claves simétricas y las vamos metiendo en los diccionarios:
        for j in retrieved_data[4]:
            # aprovechamos a meter los datos que no están encriptados
            usuario_review = retrieved_data[0][j]   # tupla 0 corresponde con la columna usuarios
            juego_review = retrieved_data[1][j]     # tupla 1 corresponde con la columna juegos

            clave_simetrica = criptografia.descifrado_asimetrico(retrieved_data[4][j], clave_privada)

            # ahora que ya tenemos la clave simétrica podemos acceder a las tuplas de reviews y scores para ir descifrándolas
            review_cifrada = retrieved_data[2][j]
            review_descifrada = criptografia.descifrado_simetrico(review_cifrada, clave_simetrica)

            score_cifrado = retrieved_data[3][j]
            score_descifrado = criptografia.descifrado_simetrico(score_cifrado, clave_simetrica)

            dic = {"usuario": usuario_review,
                   "juego": juego_review,
                   "review": review_descifrada,
                   "score": score_descifrado,
                   "clave_simetrica": clave_simetrica}

            datos_utiles.append(dic)

            j = j+1

        return datos_utiles








