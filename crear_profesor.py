import getpass
from basedatos import obtener_conexion
from werkzeug.security import generate_password_hash


if __name__ == '__main__':
    correo = input('Correo del profesor: ').strip().lower()
    contrasena = getpass.getpass('Contraseña: ')
    contrasena_confirm = getpass.getpass('Confirmar contraseña: ')

    if contrasena != contrasena_confirm:
        print('❌ Las contraseñas no coinciden')
        exit(1)

    contrasena_hash = generate_password_hash(contrasena)

    conexion = obtener_conexion()
    cur = conexion.cursor()

    try:
        cur.execute(
            'INSERT INTO usuario (correo, contrasena_hash, rol) VALUES (%s, %s, %s)',
            (correo, contrasena_hash, 'profesor')
        )
        conexion.commit()
        print(f'✅ Profesor {correo} creado correctamente')
    except Exception as e:
        conexion.rollback()
        print('❌ Error:', e)
    finally:
        cur.close()
        conexion.close()
