import os
import psycopg2
from dotenv import load_dotenv
load_dotenv()

def obtener_conexion():
    conexion = psycopg2.connect(
    host="dpg-d3j8e39gv73c73blb8m0-a.oregon-postgres.render.com",
    database="notificaciones_insedomau_bd",
    user="notificaciones_insedomau_bd_user",
    password="GqRdG22wJ7RKROK6sDhR7QrjEs8CjzvV",
    port=5432
)

    return conexion


print(repr(os.environ.get("DATABASE_URL")))
