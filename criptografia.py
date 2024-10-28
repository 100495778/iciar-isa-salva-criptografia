# este archivo contendrá todas las funciones relacionadas con encriptar.
import os

from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def cifrado_simetrico(datos, key):
    """ Esta funcion encripta los datos usando la clave "key". Se usará el cifrado simétrico AES, ya que es
    altamente usado, nos permite usar varios tamaños de clave y es muy rápido.
    """
    # Primero pasamos los datos a bytes
    datos_bytes = bytes(datos, 'ascii')

    # definimos el cifrador con la clave simétrica y definimos el vector de inicialización como un número random
    initialization_vector = os.urandom(16)     # de tamaño de bloque 16 bytes, con lo que trabaja AES

    cifrador = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), default_backend())
    encriptador = cifrador.encryptor()

    # encriptamos los datos
    datos_encriptados = encriptador.update(datos_bytes) + encriptador.finalize()

    return initialization_vector, datos_encriptados


def descifrado_simetrico(datos_encriptados, key):
    """Esta función desencripta los datos encriptados con AES"""
    initialization_vector = datos_encriptados[:16]      # los primeros 16 bytes de los datos encriptados conrresponden con el iv

    cifrador = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), default_backend())
    desencriptador = cifrador.decryptor()

    datos = desencriptador.update(datos_encriptados[16:]) + desencriptador.finalize()

    return datos



def cifrado_asimetrico(datos, clave_publica):
    """Esta función la usaremos para poder intercambiar las claves simétricas de una forma segura. Usamos la clave
    pública para encriptar los datos. Usaremos RSA. """
    # primero serializamos los datos a encriptar (nuestra clave simétrica)
    datos_cifrar = bytes(datos, 'ascii')

    ciphertext = clave_publica.encrypt(
        datos_cifrar,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label = None
        ))

    return ciphertext

def descifrado_asimetrico(datos_cifrados, clave_privada):
    """Esta función se usará para conseguir los datos del cifrado asimétrico usando la clave privada del usuario
    que corresponda. Así descifraremos la clave asimétrica que se necesita para obtener la review que se requiera."""

    datos_descifrados = clave_privada.decrypt(
        datos_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return datos_descifrados

def derivar_pwd_usuario(password):
    """Función que se encarga de derivar la clave del registro"""
    # Genera un salt y genera un kdf
    salt = os.urandom(16)  # generamos un salt aletorio

    """kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )"""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    # Se devuelven los datos necesarios en la base de datos, la psw ya está encriptada
    psw = kdf.derive(bytes(password, 'ascii'))
    # b64_salt = base64.b64encode(salt) he estado informandome y esto es pa imagenes y pa interfaces
    # salt_final = b64_salt.decode('ascii')
    return psw, salt

def verificar_pwd_usuario(pass_hash, plain_pass, salt):
    """Función que se encarga de verificar una clave"""

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )

    psw = kdf.derive(bytes(plain_pass, 'ascii'))
    if psw == pass_hash:
        return True
    return False

def generar_clave_asymm():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def guardar_clave_asymm(priv_key):
    # serializamos la private key
    pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    #guardamos la clave en el archivo pem
    with open("private_key_protected.pem", "wb") as key_file:
        key_file.write(pem)


def leer_private_key(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key