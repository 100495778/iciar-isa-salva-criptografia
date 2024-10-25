# Este archivo se encargará de definir la clase usuarios, con su tipo y funcionalidades
class Usuario:
    def __init__(self, tipo):
        self.tipo = tipo


class Cliente(Usuario):
    def __init__(self, tipo, dni, nombre, apellido1, apellido2):
        super().__init__(self)
        self.dni = dni
        self.nomre = nombre
        self.apellido1 = apellido1
        self.apellido2 = apellido2


