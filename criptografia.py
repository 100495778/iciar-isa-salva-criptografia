# este archivo contendrá todas las funciones relacionadas con encriptar.
import base64
import hashlib
import hmac
import os
import logging
from logging import raiseExceptions

from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from certificados import verificar_clave_firma

path_certs_folder = "certificados"

def create_dir(user):
    try:
        os.mkdir(path_certs_folder + "/" + user)
    except FileExistsError:
        print("El directorio ya existe")
    return

def cifrado_simetrico(datos, key):
    """ Esta funcion encripta los datos usando la clave "key". Se usará el cifrado simétrico AES, ya que es
    altamente usado, nos permite usar varios tamaños de clave y es muy rápido.
    """
    # Primero pasamos los datos a bytes
    datos_bytes = bytes(datos, 'ascii')

    # definimos el cifrador con la clave simétrica y definimos el vector de inicialización como un número aleatorio
    initialization_vector = os.urandom(16)     # de tamaño de bloque 16 bytes, con lo que trabaja AES

    cifrador = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), default_backend())
    encriptador = cifrador.encryptor()

    # encriptamos los datos
    datos_encriptados = encriptador.update(datos_bytes) + encriptador.finalize()

    return initialization_vector + datos_encriptados


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
    datos_cifrar = datos
    clave_publica = serialization.load_pem_public_key(clave_publica, default_backend())

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

def guardar_clave_asymm(priv_key, usuario, user_password):
    # serializamos la private key
    pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(user_password, 'ascii'))
    )
    #guardamos la clave en el archivo pem
    create_dir(usuario)
    path = path_certs_folder + "/" + usuario + "/" + "private_key.pem"
    with open(path, "wb") as key_file:
        key_file.write(pem)

    return


def guardar_clave_asymm_firma(priv_key, usuario, user_password):
    # serializamos la private key
    pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(user_password, 'ascii'))
    )
    #guardamos la clave en el archivo pem
    create_dir(usuario)
    path = path_certs_folder + "/" + usuario + "/" + "private_key_firma.pem"
    with open(path, "wb") as key_file:
        key_file.write(pem)

    return


def leer_private_key(path, user_password):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(user_password, 'ascii'),
        )
    return private_key

def leer_hmac_key(path, user_password):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(user_password, 'ascii'),
        )

        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # O con alguna encriptación si lo deseas
        )
    return pem



def hmac_review(review, priv_key, symm_key):
    # Configuración del log para mostrar el resultado y detalles
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # Crear un HMAC del mensaje usando SHA-256
    hmac_resultado = hmac.new(priv_key, review, hashlib.sha256).hexdigest()
    # Log del resultado de autenticación, tipo de algoritmo y longitud de clave
    leng = len(priv_key) * 8
    logging.info(f"Resultado de autenticación HMAC:  {hmac_resultado}")
    logging.info(f"Algoritmo utilizado: HMAC-SHA-256")
    logging.info(f"Longitud de la contraseña: {leng}")

    return hmac_resultado

def hmac_verificacion(mensaje, priv_key, hmac_guardado):

    # cargar el hmac guardado

    hmac_calculado = hmac.new(priv_key, mensaje, hashlib.sha256).hexdigest()

    leng = len(priv_key) * 8
    logging.info(f"Resultado de autenticación HMAC:  {hmac_calculado}")
    logging.info("Algoritmo utilizado: HMAC-SHA-256")
    logging.info(f"Longitud de la contraseña: {leng}")

    if hmac_guardado == hmac_calculado:
        logging.info("El mensaje es auténtico y no ha sido alterado.")
    else:
        logging.warning("El mensaje puede haber sido alterado.")

    return



# para la firma digital vamos a generar un par de claves asimétricas distinto al
# usado para la compartición de la clave secreta

def generar_firma(datos, clave_privada_emisor):
    """Esta función se encarga de generar un par de claves asimétricas, generar un
    hash del mensaje emisor usando SHA-256, y cifrarlo con la clave privada del
    emisor usando RSA"""

    #clave_publica_emisor, clave_privada_emisor = generar_clave_asymm()

    # hacemos el hash del mensaje
    objeto_hash = hashes.Hash(hashes.SHA256())
    #objeto_hash.update(bytes(str(datos), 'ascii'))
    objeto_hash.update(datos)   # le pasamos los datos ya directamente en bytes (en gestionReviews)
    hash_mensaje = objeto_hash.finalize()

    # procedemos a firmar
    firma = clave_privada_emisor.sign(
        hash_mensaje,  # El hash calculado
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    logging.info("Algoritmo usado para firmar: SHA256 con RSA. Longitud de clave utilizada: %s", clave_privada_emisor.key_size )
    return firma

def verificar_firma(datos_firmados, mensaje_recibido, clave_publica_emisor, usuario):
    """Esta función se encarga de descifrar con la clave pública del emisor la firma,
    hacer un hash con el mensaje que el receptor ha recibido, y comparar ambos
    resultados"""

    # calculamos un hash con el mensaje recibido:
    objeto_hash = hashes.Hash(hashes.SHA256())
    #objeto_hash.update(bytes(str(mensaje_recibido), 'ascii'))
    objeto_hash.update(mensaje_recibido)
    hash_mensaje = objeto_hash.finalize()

    try:
        clave_publica_emisor.verify(
            datos_firmados,
            hash_mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logging.info("Firma válida: Los datos no han sido alterados. El mensaje es auténtico e integro.")
    except:
        logging.warning("Firma inválida: El mensaje puede haber sido alterado.")

    verificar_clave_firma(usuario, clave_publica_emisor)

    return