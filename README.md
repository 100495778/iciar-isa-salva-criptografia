# Participantes:
Salvador Ayala Iglesias - 100495832
Isabel Hernanz García - 100495778
Iciar Garcia Izquierdo - 100495789

# Importante:
Para ejecutar la aplicación, hay que ejecutar el script "db_create.py". 
Este script borra la base de datos (en caso de existir) y la crea desde cero.
```bash
python3 ./db_create.py
```
Una vez creada la base de datos, se puede ejecutar la aplicación con el script "main.py".
```bash
python3 ./main.py
```

Para usar certificados, se debe crear antes el certificado de la entidada certificadora,
ejecutando el script "certificados/AC/generate_admin_cert.py" Se pedirá una contraseña, la 
cual se debe recordar para su posterior uso.
```bash
python3 ./certificados/AC/generate_admin_cert.py
```

# Estructura del proyecto:
Dentro de la carpeta clases se encuentran las clases que se usan para facilitar el manejo de los datos.

Dentro de la carpeta graphics se encuentran las definiciones de todos los elementos gráficos que se usan en 
la interfaz gráfica, para la cual se ha usado tkinter.

En el directorio raiz se encuentran los dos scripts mencionados anteriormente, así como los archivos
funciones_interfaz.py, gestionReviews.py y criptografia.py.

El primero contiene las funciones necesarias para la lógica de la interfaz gráfica.

El segundo contiene las funciones necesarias para extraer y guardar información en la base de datos más comodamente.

El tercero contiene las funciones relacionadas con el cifrado de datos y la generación de claves.

# Certificados:

**Importante: todo lo siguiente se ejecuta desde "certificados/AC"**
- Nota: si se usa linux, quizá sea necesario cambiar las barras invertidas por barras normales.
- Recordar usar el nombre del usuario en lugar de \<usuario\>.
- Al pedir la contraseña, usar la misma que se usó para crear el certificado de la AC.
- Una vez generado, se debe "enviar" al usuario (es decir, copiarlo a la carpeta con nombre usuario).

Para verificar datos de la solicitud de certificado una vez creada:
```bash
openssl req -in .\requests\<usuario>_csr.pem -text -noout
```

Para generar un certificado a partir de una solicitud:
```bash
openssl x509 -req -in .\requests\<usuario>_csr.pem -CA .\certificates\AC_cert.pem -CAkey .\private\AC_private_key.pem -CAcreateserial -out .\certificates\<usuario>_cert.pem -days 30 -sha256
```

Para verificar un certificado:
```bash
openssl verify -CAfile .\certificates\AC_cert.pem .\certificates\<usuario>_cert.pem
```
