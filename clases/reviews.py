# Este archivo definirá la clase de reservas
import usuarios
import json

class Review:
    def __init__(self, usuario:str,
                 juego ):
        self. usuario = usuario    # sera un objeto de la clase usuarios
        self.juego = juego      # el juego a reservar


