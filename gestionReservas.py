# Este archivo servirá para las acciones correspondientes a las reservas de los juegos
import usuarios
import reservas

class gestionReservas:
    def __init__(self):
        self.reservas = []  # creamos una lista vacia donde iran las reservas, luego se pondra en diccionario para json

    # esta funcion mete las reservas en el json de reservas hechas
    def crearReserva(self, reserva):
        ...

    def crearJson(self):
        # hacemos un diccionario vacio en el que cada conjunto sera una reserva
        json_datos = {}
        json_datos ['reservas'] = []

        for i in self.reservas:
            ...



