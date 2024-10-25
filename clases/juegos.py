class Juego():
    def __init__(self, nombre, genero, precio, publicacion):
        self.nombre = nombre
        self.genero = genero
        self.precio = precio
        self.publicacion = publicacion

    def __str__(self):
        return f"{self.nombre} - {self.genero} - {self.precio} - {self.publicacion}"