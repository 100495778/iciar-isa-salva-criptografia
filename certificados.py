from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

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