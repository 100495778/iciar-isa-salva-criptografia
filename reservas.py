# Este archivo definirá la clase de reservas
import usuarios
import json

class Reserva:
    def __init__(self, usuario,
                 juego,
                 fecha_reserva,
                 fecha_finalizacion ):
        self. usuario = usuario    # sera un objeto de la clase usuarios
        self.juego = juego      # el juego a reservar
        self.fecha_reserva = fecha_reserva      # será la fecha de inicio de la reserva
        self.fecha_finalizacion = fecha_finalizacion        # será la fecha de finalización de la reserva

