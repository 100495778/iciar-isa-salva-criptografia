import sqlite3 as sql

"""
Aviso: ejecutar este script borra la base de datos y la crea desde cero.
"""

con = sql.connect("DataBase.db") # Crea/usa la tabla
cur = con.cursor()
cur.execute("PRAGMA foreign_keys = ON;") # Para bases relacionales

try: # Crear de cero
    cur.execute("DROP TABLE reviews")
    cur.execute("DROP TABLE games")
    cur.execute("DROP TABLE users")
except:
    print("oof")

cur.execute("""CREATE TABLE users(  user TEXT,
                                    password_hash TEXT,
                                    salt TEXT,
                                    public_key TEXT,
                                    PRIMARY KEY (user))""")

cur.execute("""CREATE TABLE games(  game TEXT,
                                    publication TEXT,
                                    gender TEXT,
                                    PRIMARY KEY (game))""")

cur.execute("""CREATE TABLE reviews(user TEXT,
                                    game TEXT,
                                    review_encrypted TEXT,
                                    review_key TEXT,
                                    PRIMARY KEY (user,game),
                                    FOREIGN KEY (user) REFERENCES users(user),
                                    FOREIGN KEY (game) REFERENCES games(game))""")

con.commit()
con.close() # commit y cerrar
