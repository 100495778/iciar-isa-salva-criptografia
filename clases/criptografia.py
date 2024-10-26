# este archivo contendrá todas las funciones relacionadas con encriptar.
import os

from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
import os


def encriptado_simetrico(datos, key):
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


def desencriptado_simetrico(datos_encriptados, key):
    """Esta función desencripta los datos encriptados con AES"""
    initialization_vector = datos_encriptados[:16]      # los primeros 16 bytes de los datos encriptados conrresponden con el iv

    cifrador = Cipher(algorithms.AES(datos_encriptados), modes.CFB(initialization_vector), default_backend())
    desencriptador = cifrador.decryptor()

    datos = desencriptador.update(datos_encriptados[16:]) + desencriptador.finalize()

    return datos

