# Este archivo definirá la clase de reservas
class Reserva:
    def __init__(self, dni,
                 nombre,
                 apellido1,
                 apellido2,
                 juego,
                 fecha_reserva,
                 fecha_finalizacion ):
        self.dni = dni      # dni del cliente: Será el identificador del mismo
        self.nombre = nombre        # nombre del cliente
        self.apellido1 = apellido1       # apellido del cliente
        self.apellido2 = apellido2
        self.juego = juego      # el juego a reservar
        self.fecha_reserva = fecha_reserva      # será la fecha de inicio de la reserva
        self.fecha_finalizacion = fecha_finalizacion        # será la fecha de finalización de la reserva