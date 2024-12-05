from cryptography import x509
from cryptography.x509.oid import NameOID

# generate certificate request
AC_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganés"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Forojuegos"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Forojuegos AC"),
])