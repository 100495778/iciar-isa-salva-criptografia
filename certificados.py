from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

import logging

def generate_cert_request(user, password, name, pais, comunidad, localidad):
	# Cargarmos la clave privada
	with open("certificados/"+user+"/private_key_firma.pem", "rb") as f:
		private_key = serialization.load_pem_private_key(
			f.read(),
			password=bytes(password, 'utf-8'))

	# Generamos el CSR
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, pais[:2].upper()),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, comunidad),
		x509.NameAttribute(NameOID.LOCALITY_NAME, localidad),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Forojuegos"),
		x509.NameAttribute(NameOID.COMMON_NAME, name),
	])).sign(private_key, hashes.SHA256())

	# "Enviamos" el CSR
	with open("certificados/AC/requests/"+user+"_csr.pem", "wb") as f:
		f.write(csr.public_bytes(serialization.Encoding.PEM))

def request_exists(user):
	try:
		with open("certificados/AC/requests/"+user+"_csr.pem", "rb") as f:
			f.read()
			return True
	except FileNotFoundError:
		return False

def verificar_clave_firma(user, clave_pub_firma):
	"""Esta función se encarga de cargar el verificado del usuario, obtener la clave pública que
	contiene este verificado, y compararla con la clave pública que usan las funciones de
	firma. De esta forma tendremos asegurado que la firma tampoco ha podido ser alterada"""

	try:
		with open("certificados/"+user+"/"+user+"_cert.pem", "rb") as archivo_certificado:
			certificado_pem = archivo_certificado.read()
	except FileNotFoundError:
		try:
			with open("certificados/AC/certificates/"+user+"_cert.pem", "rb") as archivo_certificado:
				certificado_pem = archivo_certificado.read()
		except FileNotFoundError:
			logging.warning("No existe el certificado. El autor de la reseña puede no ser auténtico.")
			return

	certificado_user = load_pem_x509_certificate(certificado_pem, default_backend())

	clave_pub_certificado = certificado_user.public_key()

	#serializo ambas claves con un formato de texto estándar como es el PEM para poder compararlas
	clave_certificado_pem = clave_pub_certificado.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	clave_firma_pem = clave_pub_firma.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	if clave_firma_pem == clave_certificado_pem:
		logging.info("La clave utilizada en la firma digital coincide con la firma del certificado del usuario. Autor de la reseña auténtico.")
	else:
		logging.warning("La clave utilizada en la firma digital no coincide con la firma del certificado del usuario. El autor de la reseña puede no ser auténtico.")
