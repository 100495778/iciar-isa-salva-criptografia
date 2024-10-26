# Este archivo se encargará de definir la clase Usuario, con su tipo y funcionalidades
import os
import sqlite3 as sql
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import criptografia
con = sql.connect("base_de_datos.db")
cur = con.cursor()
class Cliente:
    def __init__(self, tipo, dni, nombre, apellido1, apellido2, clave_publica):
        super().__init__(self)
        self.dni = dni
        self.nomre = nombre
        self.apellido1 = apellido1
        self.apellido2 = apellido2
        self.clave_publica = clave_publica

    def registrarse(self, usuario, password, password_rep):
        if len(password) < 8:
            # la contraseña es demasiado corta
            raise ValueError("METELE MAS DATA")
        if password_rep != password:
            raise ValueError("metele mas datos correctamente")

        else:
            try:
                pwd, salt = criptografia.derivar_pwd_usuario(password)
                # public_key = os.urandom(32)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()
                cur.execute("INSERT INTO usuarios VALUES (?,?,? ?)", (usuario, password, salt, public_key))

            except sql.IntegrityError:
                raise ValueError("ya existe un usuario")

        # ahora generamos la private key y la guardamos
        public_key = private_key.public_key()
        # hay q alamacenarla en base64 porque asi es el formato .pem
        with open("clave_privada.pem", "wb") as archivo_clave:
            archivo_clave.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                    # Para proteger con contraseña, se usa BestAvailableEncryption
                )
            )

