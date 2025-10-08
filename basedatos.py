# basedatos.py
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def obtener_conexion():
    conexion = psycopg2.connect(
        os.environ.get("DATABASE_URL"))
    return conexion
