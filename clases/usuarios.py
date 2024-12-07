# Este archivo se encargará de definir la clase Usuario, con su tipo y funcionalidades
import sqlite3 as sql
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import criptografia

class Cliente:
    def __init__(self, tipo, usuario, password, clave_publica, public_key_firma):
        super().__init__(self)
        self.usuario = usuario
        self.password = password
        self.clave_publica = clave_publica
        self.public_key_firma = public_key_firma



