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
    def __init__(self, tipo, usuario, password, clave_publica):
        super().__init__(self)
        self.usuario = usuario
        self.password = password
        self.clave_publica = clave_publica

    def registrarse(self, usuario, password, password_rep):
        if len(password) < 8:
            # la contraseña es demasiado corta
            raise ValueError("METELE MAS DATA")
        if password_rep != password:
            raise ValueError("Introduce la contraseña correctamente")

        else:
            try:
                pwd, salt = criptografia.derivar_pwd_usuario(password)
                # public_key = os.urandom(32)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()
                cur.execute("INSERT INTO usuarios VALUES (?,?,? ?)", (usuario, password, salt, public_key))

            except sql.IntegrityError:
                raise ValueError("Ya existe un usuario")

        # ahora generamos la private key y la guardamos

        public_key = private_key.public_key()
        # Se alamacena en base 64 porque asi es el formato .pem
        with open("clave_privada.pem", "wb") as archivo_clave:
            archivo_clave.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                    # Para proteger con contraseña, se usa BestAvailableEncryption
                )
            )

