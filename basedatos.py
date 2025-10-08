# basedatos.py
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def obtener_conexion():
    conexion = psycopg2.connect(
        host=os.getenv('PG_HOST'),
        port=os.getenv('PG_PORT'),
        database=os.getenv('PG_DATABASE'),
        user=os.getenv('PG_USER'),
        password=os.getenv('PG_PASSWORD')
    )
    return conexion
