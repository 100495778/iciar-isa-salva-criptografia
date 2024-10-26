# Este archivo se encargará de definir la clase Usuario, con su tipo y funcionalidades
import sqlite3 as sql
from cryptography.hazmat.primitives.asymmetric import rsa
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

        #al crear un usuario le pedimos que repita la contraseña
        if password_rep != password:
            raise ValueError("Introduce la contraseña correctamente")

        else:
            try:
                pwd, salt = criptografia.derivar_pwd_usuario(password)
                # public_key = os.urandom(32)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()
                cur.execute("INSERT INTO usuarios VALUES (?,?,? ?)", (usuario, password, salt, public_key))

            # EL USUARIO introducido ya existe
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

    def comprobar_contraseña_inicio_sesion(self, usuario, password):
        """metodo que ayuda a comprobar que la contraseña introducida al iniciar sesión
        corresponde con la del usuario
        Returnea false en caso de que no coincidan"""
        cur.execute("select password_hash, salt from usuarios where user=?", (usuario,))
        rows = cur.fetchall()

        if rows == []:
            # no hay un usuario con ese nombre
            return False
        else:
            # Si se encuentra al usuario, intenta verificarlo con la contraseña, el token y el salt
            try:
                salt = rows[0][1]
                hash = rows[0][0]
                #verificar(password, res[0][0], res[0][1])
                bytes_salt = bytes(salt, 'ascii')
                #bytes_salt = base64.b64decode(bytes_b64_salt)
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2 ** 14,
                    r=8,
                    p=1,
                )
                # Se devuelven los datos necesarios en la base de datos, la psw ya está encriptada
                psw = kdf.derive(bytes(password, 'ascii'))
                if hash == psw:
                    return True
                else:
                    return False
            except:
                # Si no se verifica el usuario, returnea False

                return False


