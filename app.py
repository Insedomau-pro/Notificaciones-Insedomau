# aplicacion.py
# Aplicación Flask completa - variables y rutas en español

import os
import uuid
import smtplib
import math
from email.message import EmailMessage
from flask import (
    Flask, request, redirect, render_template, session,
    Response, send_from_directory, url_for, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from basedatos import obtener_conexion
from dotenv import load_dotenv
import psycopg2
import click

# ----------------- Configuración inicial -----------------
load_dotenv()

aplicacion = Flask(__name__)

from flask_mail import Mail, Message

# Configuración de Flask-Mail
aplicacion.config['MAIL_SERVER'] = os.getenv("MAIL_SERVIDOR")
aplicacion.config['MAIL_PORT'] = int(os.getenv("MAIL_PUERTO"))
aplicacion.config['MAIL_USERNAME'] = os.getenv("MAIL_USUARIO")
aplicacion.config['MAIL_PASSWORD'] = os.getenv("MAIL_CONTRASENA")
aplicacion.config['MAIL_USE_TLS'] = os.getenv("MAIL_USAR_TLS") == "True"
aplicacion.config['MAIL_USE_SSL'] = False
aplicacion.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USUARIO")


mail = Mail(aplicacion)

aplicacion.config['SECRET_KEY'] = os.getenv('CLAVE_SECRETA', 'desarrollo')
aplicacion.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))

# configuración de correo
MAIL_SERVIDOR = os.getenv('MAIL_SERVIDOR')
MAIL_PUERTO = int(os.getenv('MAIL_PUERTO', 587))
MAIL_USUARIO = os.getenv('MAIL_USUARIO')
MAIL_CONTRASENA = os.getenv('MAIL_CONTRASENA')
MAIL_USAR_TLS = os.getenv('MAIL_USAR_TLS', 'True') == 'True'

# directorio para archivos en disco
DIRECTORIO_ARCHIVOS = os.path.join(os.path.dirname(__file__), 'archivos')
os.makedirs(DIRECTORIO_ARCHIVOS, exist_ok=True)

# extensiones permitidas
EXT_PERMITIDAS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'}
MIME_IMAGENES = ('image/jpeg', 'image/png', 'image/gif')

# ----------------- helpers de seguridad -----------------
def generar_token_csrf():
    token = uuid.uuid4().hex
    session['csrf_token'] = token
    return token

def verificar_token_csrf(token_form):
    token_sesion = session.get('csrf_token')
    return token_sesion and token_form == token_sesion

# ----------------- helpers de usuario -----------------
def usuario_logueado():
    return session.get('usuario_id') is not None

def obtener_usuario_actual():
    uid = session.get('usuario_id')
    if not uid:
        return None
    conexion = obtener_conexion()
    cur = conexion.cursor()
    cur.execute('SELECT id, correo, rol FROM usuario WHERE id=%s', (uid,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()
    if fila:
        return {'id': fila[0], 'correo': fila[1], 'rol': fila[2]}
    return None

# hacer que obtener_usuario_actual, session y csrf_token estén disponibles en plantillas
@aplicacion.context_processor
def context_processor_global():
    # aseguramos que siempre exista un token CSRF en sesión
    if not session.get('csrf_token'):
        generar_token_csrf()
    return {
        'obtener_usuario_actual': obtener_usuario_actual,
        'session': session,
        'csrf_token': session.get('csrf_token')
    }

# ----------------- Cabeceras de seguridad -----------------
@aplicacion.after_request
def add_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    # CSP básica: ajustar según necesidad
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
    return response

# ----------------- RUTAS DE AUTENTICACIÓN -----------------
@aplicacion.route('/iniciar_sesion', methods=['GET', 'POST'])
def iniciar_sesion():
    if request.method == 'GET':
        token = generar_token_csrf()
        return render_template('iniciar_sesion.html', token=token)

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    correo = request.form.get('correo', '').strip().lower()
    contrasena = request.form.get('contrasena', '')

    conexion = obtener_conexion()
    cur = conexion.cursor()
    cur.execute('SELECT id, contrasena_hash FROM usuario WHERE correo=%s', (correo,))
    fila = cur.fetchone()

    if not fila:
        cur.close()
        conexion.close()
        flash('Usuario o contraseña incorrectos')
        return redirect(url_for('iniciar_sesion'))

    uid, contrasena_hash = fila
    if not check_password_hash(contrasena_hash, contrasena):
        cur.close()
        conexion.close()
        flash('Usuario o contraseña incorrectos')
        return redirect(url_for('iniciar_sesion'))

    # login correcto: regeneramos sesión mínima y token CSRF
    session.clear()
    session['usuario_id'] = uid
    generar_token_csrf()
    cur.close()
    conexion.close()
    return redirect('/noticias')

@aplicacion.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'GET':
        token = generar_token_csrf()
        return render_template('registrar.html', token=token)

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    correo = request.form.get('correo', '').strip().lower()
    contrasena = request.form.get('contrasena', '')

    if not correo or not contrasena:
        flash('Correo y contraseña son obligatorios')
        return redirect(url_for('registrar'))

    contrasena_hash = generate_password_hash(contrasena)
    conexion = obtener_conexion()
    cur = conexion.cursor()
    try:
        cur.execute(
            "INSERT INTO usuario (correo, contrasena_hash, rol) VALUES (%s,%s,%s) RETURNING id",
            (correo, contrasena_hash, 'estudiante')
        )
        uid = cur.fetchone()[0]
        conexion.commit()
    except Exception:
        conexion.rollback()
        cur.close()
        conexion.close()
        flash('No se pudo crear el usuario: correo quizá ya registrado')
        return redirect(url_for('registrar'))

    cur.close()
    conexion.close()
    # sesión nueva + token CSRF
    session.clear()
    session['usuario_id'] = uid
    generar_token_csrf()
    return redirect('/noticias')

@aplicacion.route('/cerrar_sesion', methods=['POST'])
def cerrar_sesion():
    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400
    session.clear()
    return redirect(url_for('iniciar_sesion'))

# ----------------- RUTAS DE NOTICIAS -----------------
@aplicacion.route('/')
def index():
    # redirige a la lista de noticias; usar URL fija evita errores de endpoint
    return redirect('/noticias')

@aplicacion.route('/noticias')
def noticias_lista():
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))
    pagina = int(request.args.get('page', 1))
    por_pagina = 10
    offset = (pagina - 1) * por_pagina

    conexion = obtener_conexion()
    cur = conexion.cursor()
    cur.execute('SELECT id, titulo, cuerpo, publicada_en FROM noticia ORDER BY publicada_en DESC LIMIT %s OFFSET %s', (por_pagina, offset))
    noticias = cur.fetchall()
    cur.execute('SELECT COUNT(*) FROM noticia')
    total = cur.fetchone()[0]
    cur.close()
    conexion.close()

    paginas_totales = math.ceil(total / por_pagina) if total else 1
    return render_template('noticias_lista.html', noticias=noticias, pagina=pagina, paginas_totales=paginas_totales)

# detalle de noticia
@aplicacion.route('/noticias/<int:noticia_id>')
def noticias_detalle(noticia_id):
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))

    conexion = obtener_conexion()
    cur = conexion.cursor()

    # Traer la noticia
    cur.execute(
        'SELECT id, titulo, cuerpo, autor_id, publicada_en '
        'FROM noticia WHERE id = %s',
        (noticia_id,)
    )
    noticia = cur.fetchone()

    if not noticia:
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Noticia no encontrada'), 404

    # Traer adjuntos asociados a esa noticia
    cur.execute("""
        SELECT id, nombre_original, tipo_mime, modo_almacenamiento
        FROM adjunto
        WHERE noticia_id = %s
    """, (noticia_id,))
    adjuntos = cur.fetchall()


    cur.close()
    conexion.close()

    return render_template(
        'noticias_detalle.html',
        noticia=noticia,
        adjuntos=adjuntos
    )


# crear noticia (solo profesores)
@aplicacion.route('/noticias/crear', methods=['GET', 'POST'])
def noticias_crear():
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'profesor':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    if request.method == 'GET':
        token = generar_token_csrf()
        return render_template('noticias_formulario.html', token=token)

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    titulo = request.form.get('titulo', '').strip()
    cuerpo = request.form.get('cuerpo', '').strip()
    if not titulo or not cuerpo:
        flash('Título y cuerpo son obligacontorios')
        return redirect('/noticias/crear')

    conexion = obtener_conexion()
    cur = conexion.cursor()
    try:
        cur.execute('INSERT INTO noticia (titulo, cuerpo, autor_id) VALUES (%s,%s,%s) RETURNING id', (titulo, cuerpo, usuario['id']))
        noticia_id = cur.fetchone()[0]
        conexion.commit()
    except Exception:
        conexion.rollback()
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Error al crear la noticia'), 500

    archivos = request.files.getlist('adjuntos')
    for fichero in archivos:
        if fichero and fichero.filename:
            nombre_original = fichero.filename
            nombre_seguro = secure_filename(nombre_original)
            extension = os.path.splitext(nombre_seguro)[1].lower()
            if extension not in EXT_PERMITIDAS:
                continue
            contenido = fichero.read()
            tamano = len(contenido)
            tipo_mime = fichero.mimetype or ''
            if tipo_mime.startswith('image/'):
                try:
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, tipo_mime, tamano_bytes, modo_almacenamiento, contenido_bytea) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, tipo_mime, tamano, 'bd', psycopg2.Binary(contenido))
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()
            else:
                nombre_guardado = f"{uuid.uuid4().hex}{extension}"
                ruta_guardado = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
                try:
                    with open(ruta_guardado, 'wb') as f:
                        f.write(contenido)
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano_bytes, modo_almacenamiento) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano, 'disco')
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()
    print(">> Nombre recibido:", fichero.filename)
    cur.close()
    conexion.close()

    try:
        enviar_notificacion_correo(titulo, cuerpo, noticia_id)
    except Exception as e:
        print('Error al enviar correos:', e)

    return redirect(f'/noticias/{noticia_id}')

# editar noticia (solo profesores)
@aplicacion.route('/noticias/<int:noticia_id>/editar', methods=['GET', 'POST'])
def noticias_editar(noticia_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'profesor':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    conexion = obtener_conexion()
    cur = conexion.cursor()

    # Buscar noticia
    cur.execute('SELECT id, titulo, cuerpo FROM noticia WHERE id=%s', (noticia_id,))
    noticia = cur.fetchone()
    if not noticia:
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Noticia no encontrada'), 404

    if request.method == 'GET':
        # Traer adjuntos de la noticia
        cur.execute('SELECT id, nombre_original, nombre_guardado, modo_almacenamiento FROM adjunto WHERE noticia_id=%s', (noticia_id,))
        adjuntos = cur.fetchall()
        token = generar_token_csrf()
        cur.close()
        conexion.close()
        return render_template('noticias_formulario.html', noticia=noticia, adjuntos=adjuntos, token=token)

    # POST
    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    titulo = request.form.get('titulo', '').strip()
    cuerpo = request.form.get('cuerpo', '').strip()
    if not titulo or not cuerpo:
        flash('Título y cuerpo son obligatorios')
        return redirect(f'/noticias/{noticia_id}/editar')

    try:
        cur.execute('UPDATE noticia SET titulo=%s, cuerpo=%s WHERE id=%s', (titulo, cuerpo, noticia_id))
        conexion.commit()
    except Exception:
        conexion.rollback()
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Error al actualizar noticia'), 500

    # Procesar archivos nuevos
    archivos = request.files.getlist('adjuntos')
    for fichero in archivos:
        if fichero and fichero.filename:
            nombre_original = fichero.filename
            nombre_seguro = secure_filename(nombre_original)
            extension = os.path.splitext(nombre_seguro)[1].lower()
            if extension not in EXT_PERMITIDAS:
                continue
            contenido = fichero.read()
            tamano = len(contenido)
            tipo_mime = fichero.mimetype or ''
            if tipo_mime.startswith('image/'):
                try:
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, tipo_mime, tamano_bytes, modo_almacenamiento, contenido_bytea) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, tipo_mime, tamano, 'bd', psycopg2.Binary(contenido))
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()
            else:
                nombre_guardado = f"{uuid.uuid4().hex}{extension}"
                ruta_guardado = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
                try:
                    with open(ruta_guardado, 'wb') as f:
                        f.write(contenido)
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano_bytes, modo_almacenamiento) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano, 'disco')
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()

    cur.close()
    conexion.close()
    return redirect(f'/noticias/{noticia_id}')


# eliminar noticia (solo profesores)
@aplicacion.route('/noticias/<int:noticia_id>/eliminar', methods=['POST'])
def noticias_eliminar(noticia_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'profesor':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    conexion = obtener_conexion()
    cur = conexion.cursor()
    try:
        cur.execute("SELECT nombre_guardado, modo_almacenamiento FROM adjunto WHERE noticia_id=%s", (noticia_id,))
        filas = cur.fetchall()
        for nombre_guardado, modo in filas:
            if modo == 'disco' and nombre_guardado:
                ruta = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
                try:
                    os.remove(ruta)
                except Exception:
                    pass
        cur.execute('DELETE FROM noticia WHERE id=%s', (noticia_id,))
        conexion.commit()
    except Exception:
        conexion.rollback()
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Error al eliminar noticia'), 500

    cur.close()
    conexion.close()
    return redirect('/noticias')

# subir adjuntos a noticia existente (solo profesores)
@aplicacion.route('/noticias/<int:noticia_id>/adjuntos/subir', methods=['POST'])
def adjuntos_subir(noticia_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'profesor':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    archivos = request.files.getlist('adjuntos')
    conexion = obtener_conexion()
    cur = conexion.cursor()
    for fichero in archivos:
        if fichero and fichero.filename:
            nombre_original = fichero.filename
            nombre_seguro = secure_filename(nombre_original)
            extension = os.path.splitext(nombre_seguro)[1].lower()
            if extension not in EXT_PERMITIDAS:
                continue
            contenido = fichero.read()
            tamano = len(contenido)
            tipo_mime = fichero.mimetype or ''
            if tipo_mime.startswith('image/'):
                try:
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, tipo_mime, tamano_bytes, modo_almacenamiento, contenido_bytea) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, tipo_mime, tamano, 'bd', psycopg2.Binary(contenido))
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()
            else:
                nombre_guardado = f"{uuid.uuid4().hex}{extension}"
                ruta_guardado = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
                try:
                    with open(ruta_guardado, 'wb') as f:
                        f.write(contenido)
                    cur.execute(
                        "INSERT INTO adjunto (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano_bytes, modo_almacenamiento) VALUES (%s,%s,%s,%s,%s,%s)",
                        (noticia_id, nombre_original, nombre_guardado, tipo_mime, tamano, 'disco')
                    )
                    conexion.commit()
                except Exception:
                    conexion.rollback()
    cur.close()
    conexion.close()
    return redirect(f'/noticias/{noticia_id}')

# eliminar adjunto (solo profesores)
# eliminar adjunto (solo profesores) - versión robusta
@aplicacion.route('/adjuntos/<int:adjunto_id>/eliminar', methods=['POST'])
def adjunto_eliminar(adjunto_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'profesor':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    conexion = obtener_conexion()
    cur = conexion.cursor()
    try:
        # Obtener datos del adjunto y noticia asociada
        cur.execute('SELECT nombre_guardado, modo_almacenamiento, noticia_id FROM adjunto WHERE id=%s', (adjunto_id,))
        fila = cur.fetchone()
        if not fila:
            cur.close()
            conexion.close()
            flash('Adjunto no encontrado', 'error')
            return redirect(request.referrer or url_for('noticias_lista'))

        nombre_guardado, modo, noticia_id = fila

        # Borrar archivo en disco si aplica
        if modo == 'disco' and nombre_guardado:
            ruta = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
            try:
                if os.path.exists(ruta):
                    os.remove(ruta)
            except Exception as e:
                # no fallamos por el borrado de archivo físico, solo lo notificamos
                print(f"[adjunto_eliminar] fallo borrando archivo en disco: {e}")

        # Eliminar registro del adjunto
        cur.execute('DELETE FROM adjunto WHERE id=%s', (adjunto_id,))
        conexion.commit()

    except Exception as e:
        conexion.rollback()
        cur.close()
        conexion.close()
        print(f"[adjunto_eliminar] excepción: {e}")
        return render_template('error.html', mensaje='Error al eliminar adjunto'), 500

    # Cerrar conexiones y redirigir a la edición de la noticia (vuelves al formulario)
    cur.close()
    conexion.close()
    flash('Adjunto eliminado correctamente', 'success')
    # Redirigimos a la edición para que veas el estado actualizado
    return redirect(url_for('noticias_editar', noticia_id=noticia_id))


# servir imagen inline desde BD
@aplicacion.route('/adjuntos/<int:adjunto_id>/inline')
def adjunto_inline(adjunto_id):
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))
    conexion = obtener_conexion()
    cur = conexion.cursor()
    cur.execute("SELECT contenido_bytea, tipo_mime FROM adjunto WHERE id=%s AND modo_almacenamiento='bd'", (adjunto_id,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()
    if not fila:
        return render_template('error.html', mensaje='Adjunto no encontrado o no es imagen'), 404
    contenido_bytea, tipo_mime = fila
    return Response(contenido_bytea, mimetype=tipo_mime, headers={'Content-Disposition': 'inline'})

# descargar adjunto (desde BD o disco)
@aplicacion.route('/adjuntos/<int:adjunto_id>/descargar')
def adjunto_descargar(adjunto_id):
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))
    conexion = obtener_conexion()
    cur = conexion.cursor()
    cur.execute("SELECT nombre_original, nombre_guardado, tipo_mime, modo_almacenamiento, contenido_bytea FROM adjunto WHERE id=%s", (adjunto_id,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()
    if not fila:
        return render_template('error.html', mensaje='Adjunto no encontrado'), 404
    nombre_original, nombre_guardado, tipo_mime, modo, contenido = fila
    if modo == 'bd' and contenido is not None:
        return Response(contenido, mimetype=tipo_mime, headers={'Content-Disposition': f'attachment; filename=\"{nombre_original}\"'})
    if modo == 'disco' and nombre_guardado:
        return send_from_directory(DIRECTORIO_ARCHIVOS, nombre_guardado, as_attachment=True, download_name=nombre_original)
    return render_template('error.html', mensaje='No se puede servir el adjunto'), 500

# -------------- envío de correos --------------
def enviar_notificacion_correo(titulo, cuerpo, noticia_id):
    with aplicacion.app_context():
        try:
            # Obtener todos los correos
            conexion = obtener_conexion()
            cursor = conexion.cursor()
            cursor.execute("SELECT correo FROM usuario")
            destinatarios = [fila[0] for fila in cursor.fetchall()]
            cursor.close()
            conexion.close()

            # Crear el mensaje
            enlace = f"http://127.0.0.1:5000/noticias/{noticia_id}"
            mensaje = Message(
                subject=f"Nueva noticia: {titulo}",
                recipients=destinatarios,
                body=f"{cuerpo}\n\nVer la noticia completa: {enlace}"
            )

            # Enviar
            mail.send(mensaje)
            print("✅ Correos enviados correctamente")

        except Exception as e:
            print("❌ Error al enviar correos:", e)


# -------------- CLI para crear profesor --------------
@aplicacion.cli.command('crear-profesor')
@click.option('--correo', prompt=True)
@click.option('--contrasena', prompt=True, hide_input=True, confirmation_prompt=True)
def crear_profesor_cli(correo, contrasena):
    contrasena_hash = generate_password_hash(contrasena)
    conexion = obtener_conexion()
    cur = conexion.cursor()
    try:
        cur.execute('INSERT INTO usuario (correo, contrasena_hash, rol) VALUES (%s,%s,%s)', (correo, contrasena_hash, 'profesor'))
        conexion.commit()
        print('Profesor creado correctamente')
    except Exception as e:
        conexion.rollback()
        print('Error al crear profesor:', e)
    finally:
        cur.close()
        conexion.close()

# -------------- ejecutar --------------
if __name__ == '__main__':
    aplicacion.run(host="0.0.0.0", port=5000, debug=True)