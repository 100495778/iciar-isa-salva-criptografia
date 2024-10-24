import json


def writeJson(data:dict, filename:str):
    with open(filename, 'w') as file:
        if file is None:
            raise Exception("Error al abrir el archivo")
        json.dump(data, file, indent=4)

def readJson(filename:str)-> dict:
    with open (filename, 'r') as file:
        if file is None:
            raise Exception("Error al abrir el archivo")
        return json.load(file)
