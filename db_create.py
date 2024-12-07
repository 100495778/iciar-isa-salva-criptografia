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
                                    pub_key_firma TEXT,
                                    PRIMARY KEY (user))""")

cur.execute("""CREATE TABLE games(  game TEXT,
                                    publication TEXT,
                                    gender TEXT,
                                    PRIMARY KEY (game))""")

cur.execute("""CREATE TABLE reviews(user TEXT,
                                    game TEXT,
                                    review_encrypted TEXT,
                                    score_encrypted TEXT,
                                    review_key TEXT,
                                    hmac_text text,
                                    verified INTEGER,
                                    firma TEXT,
                                    PRIMARY KEY (user,game),
                                    FOREIGN KEY (user) REFERENCES users(user),
                                    FOREIGN KEY (game) REFERENCES games(game))""")

for game in ("Zelda","Pokemon"):
    cur.execute("INSERT INTO games (game, publication, gender) VALUES (?, ?, ?)", (game, "2000-06-01", "Aventura"))
for game in ("COD", "Fornait"):
    cur.execute("INSERT INTO games (game, publication, gender) VALUES (?, ?, ?)", (game, "1999-02-12", "FPS"))

con.commit()
con.close() # commit y cerrar
