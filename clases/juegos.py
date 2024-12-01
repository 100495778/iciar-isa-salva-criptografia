class Juego():
    def __init__(self, nombre, genero, publicacion):
        self.nombre = nombre
        self.genero = genero
        self.publicacion = publicacion

    def __str__(self):
        return f"{self.nombre} - {self.genero} - {self.precio} - {self.publicacion}"