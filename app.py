# aplicacion.py
# Aplicación Flask completa - variables y rutas en español

import os
import requests
import uuid
import smtplib
import flask_mail
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
from psycopg2.extras import RealDictCursor
import click
from datetime import datetime
from urllib.parse import quote
from datetime import datetime, timedelta
hora = datetime.now().strftime("%H:%M:%S")

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
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id, correo, rol FROM usuario WHERE id=%s', (uid,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()
    if fila:
        return {'id': fila['id'], 'correo': fila['correo'], 'rol': fila['rol']}
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
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id, contrasena_hash FROM usuario WHERE correo=%s', (correo,))
    fila = cur.fetchone()

    if not fila:
        cur.close()
        conexion.close()
        flash('Usuario o contraseña incorrectos')
        return redirect(url_for('iniciar_sesion'))

    uid = fila['id']
    contrasena_hash = fila['contrasena_hash']
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


@aplicacion.route('/cerrar_sesion', methods=['POST'])
def cerrar_sesion():
    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400
    session.clear()
    return redirect(url_for('iniciar_sesion'))

# ----------------- RUTAS DE ADMINISTRADOR -----------------
@aplicacion.route('/admin/usuarios')
def admin_usuarios():
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'admin':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, correo, rol FROM usuario ORDER BY id ASC")
    usuarios = cur.fetchall()
    cur.close()
    conexion.close()
    return render_template('admin_usuarios.html', usuarios=usuarios, token=generar_token_csrf())


@aplicacion.route('/admin/usuarios/crear', methods=['GET', 'POST'])
def admin_crear_usuario():
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'admin':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    if request.method == 'GET':
        return render_template('admin_usuario_form.html', token=generar_token_csrf())

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    correo = request.form.get('correo', '').strip().lower()
    contrasena = request.form.get('contrasena', '')
    rol = request.form.get('rol', '').strip().lower()

    if not correo or not contrasena or rol not in ['profesor', 'estudiante', 'admin']:
        flash('Datos inválidos o incompletos')
        return redirect(url_for('admin_crear_usuario'))

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute('INSERT INTO usuario (correo, contrasena_hash, rol) VALUES (%s,%s,%s)',
                    (correo, generate_password_hash(contrasena), rol))
        conexion.commit()
        flash('Usuario creado correctamente')
    except Exception as e:
        conexion.rollback()
        flash('Error al crear usuario: ' + str(e))
    finally:
        cur.close()
        conexion.close()

    return redirect(url_for('admin_usuarios'))


@aplicacion.route('/admin/usuarios/<int:usuario_id>/editar', methods=['GET', 'POST'])
def admin_editar_usuario(usuario_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'admin':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        cur.execute("SELECT id, correo, rol FROM usuario WHERE id=%s", (usuario_id,))
        u = cur.fetchone()
        cur.close()
        conexion.close()
        if not u:
            return render_template('error.html', mensaje='Usuario no encontrado'), 404
        return render_template('admin_usuario_form.html', usuario=u, token=generar_token_csrf())

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    correo = request.form.get('correo', '').strip().lower()
    rol = request.form.get('rol', '').strip().lower()
    contrasena = request.form.get('contrasena', '')

    try:
        if contrasena:
            cur.execute("UPDATE usuario SET correo=%s, rol=%s, contrasena_hash=%s WHERE id=%s",
                        (correo, rol, generate_password_hash(contrasena), usuario_id))
        else:
            cur.execute("UPDATE usuario SET correo=%s, rol=%s WHERE id=%s",
                        (correo, rol, usuario_id))
        conexion.commit()
        flash('Usuario actualizado correctamente')
    except Exception as e:
        conexion.rollback()
        flash('Error al actualizar usuario: ' + str(e))
    finally:
        cur.close()
        conexion.close()

    return redirect(url_for('admin_usuarios'))


@aplicacion.route('/admin/usuarios/<int:usuario_id>/eliminar', methods=['POST'])
def admin_eliminar_usuario(usuario_id):
    usuario = obtener_usuario_actual()
    if not usuario or usuario.get('rol') != 'admin':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("DELETE FROM usuario WHERE id=%s", (usuario_id,))
        conexion.commit()
        flash('Usuario eliminado correctamente')
    except Exception as e:
        conexion.rollback()
        flash('Error al eliminar usuario: ' + str(e))
    finally:
        cur.close()
        conexion.close()

    return redirect(url_for('admin_usuarios'))

@aplicacion.route('/admin/cambiar_rol/<int:user_id>', methods=['POST'])
def cambiar_rol(user_id):
    usuario_actual = obtener_usuario_actual()
    if not usuario_actual or usuario_actual['rol'] != 'admin':
        return render_template('error.html', mensaje='Acceso denegado'), 403

    nuevo_rol = request.form.get('rol')
    if not nuevo_rol:
        flash("Debe seleccionar un rol válido.")
        return redirect(url_for('admin_usuarios'))

    conexion = obtener_conexion()
    cursor = conexion.cursor()
    cursor.execute("UPDATE usuarios SET rol = ? WHERE id = ?", (nuevo_rol, user_id))
    conexion.commit()
    conexion.close()

    flash("Rol del usuario actualizado correctamente.")
    return redirect(url_for('admin_usuarios'))

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
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute(
    'SELECT id, titulo, cuerpo, autor_id, publicada_en, anclada '
    'FROM noticia '
    'ORDER BY anclada DESC, publicada_en DESC '
    'LIMIT %s OFFSET %s',(por_pagina, offset))
    noticias = cur.fetchall()
    cur.execute('SELECT COUNT(*) AS total FROM noticia')
    total = cur.fetchone()['total']
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
    cur = conexion.cursor(cursor_factory=RealDictCursor)

    # Traer la noticia
    cur.execute(
        'SELECT id, titulo, cuerpo, autor_id, anclada, publicada_en '
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
# checkbox: viene "on" si está marcado
    anclada = True if request.form.get('anclada') == 'on' else False
    duracion = request.form.get('anclada_duracion')

    anclada_hasta = None
    if anclada:
        if duracion == 'permanente':
            anclada_hasta = None
        elif duracion:
            ahora = datetime.now()
            if 'hora' in duracion:
                horas = int(duracion.replace('hora',''))
                anclada_hasta = ahora + timedelta(hours=horas)
            elif 'dias' in duracion:
                dias = int(duracion.replace('hora',''))
                anclada_hasta = ahora + timedelta(days=dias)

    if not titulo or not cuerpo:
        flash('Título y cuerpo son obligatorios')
        return redirect('/noticias/crear')

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute('INSERT INTO noticia (titulo, cuerpo, autor_id, anclada, anclada_hasta) VALUES (%s,%s,%s,%s,%s) RETURNING id', 
                    (titulo, cuerpo, usuario['id'], anclada, anclada_hasta)
                    )
        noticia_id = cur.fetchone()['id']
        conexion.commit()
    except Exception:
        conexion.rollback()
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Error al crear la noticia: {e}'), 500

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
    cur = conexion.cursor(cursor_factory=RealDictCursor)

    # Buscar noticia
    cur.execute('SELECT id, titulo, cuerpo, autor_id, anclada FROM noticia WHERE id=%s', (noticia_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Noticia no encontrada'), 404

    # Verificar que el usuario logueado es el autor
    if fila['autor_id'] != usuario['id']:
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Acceso denegado: solo el autor puede editar esta noticia'), 403

    noticia = {
        'id': fila['id'],
        'titulo': fila['titulo'],
        'cuerpo': fila['cuerpo'],
        'autor_id': fila['autor_id'],
        'anclada': fila['anclada']
    }

    if request.method == 'GET':
        # Traer adjuntos
        cur.execute('SELECT id, nombre_original, nombre_guardado, modo_almacenamiento FROM adjunto WHERE noticia_id=%s', (noticia_id,))
        adjuntos = cur.fetchall()
        token = generar_token_csrf()
        cur.close()
        conexion.close()
        return render_template('noticias_formulario.html', noticia=noticia, adjuntos=adjuntos, token=token)

    # POST
    token = request.form.get('csrf_token')
    if not verificar_token_csrf(token):
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Token CSRF inválido'), 400

    titulo = request.form.get('titulo', '').strip()
    cuerpo = request.form.get('cuerpo', '').strip()
    anclada = request.form.get('anclada') == 'on'

    if not titulo or not cuerpo:
        flash('Título y cuerpo son obligatorios')
        cur.close()
        conexion.close()
        return redirect(f'/noticias/{noticia_id}/editar')

    try:
        cur.execute('UPDATE noticia SET titulo=%s, cuerpo=%s, anclada=%s WHERE id=%s',
                    (titulo, cuerpo, anclada, noticia_id))
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
    cur = conexion.cursor(cursor_factory=RealDictCursor)

    cur.execute('SELECT autor_id FROM noticia WHERE id=%s', (noticia_id,))
    fila = cur.fetchone()

    if not fila:
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Noticia no encontrada'), 404
    
    autor_id_db = fila['autor_id']
    if autor_id_db != usuario.get('id'):  # <- uso get para evitar KeyError
        cur.close()
        conexion.close()
        return render_template('error.html', mensaje='Acceso denegado: solo el autor puede eliminar esta noticia'), 403

    try:
        # eliminar archivos asociados
        cur.execute("SELECT nombre_guardado, modo_almacenamiento FROM adjunto WHERE noticia_id=%s", (noticia_id,))
        filas = cur.fetchall()
        for nombre_guardado, modo in filas:
            if modo == 'disco' and nombre_guardado:
                ruta = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
                try:
                    os.remove(ruta)
                except Exception:
                    pass

        # eliminar noticia
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
    cur = conexion.cursor(cursor_factory=RealDictCursor)
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
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        # Obtener datos del adjunto y noticia asociada
        cur.execute('SELECT nombre_guardado, modo_almacenamiento, noticia_id FROM adjunto WHERE id=%s', (adjunto_id,))
        fila = cur.fetchone()
        if not fila:
            cur.close()
            conexion.close()
            flash('Adjunto no encontrado', 'error')
            return redirect(request.referrer or url_for('noticias_lista'))

        nombre_guardado = fila['nombre_guardado']
        modo = fila['modo_almacenamiento']
        noticia_id = fila['noticia_id']


        # Verificar autor de la noticia
        cur.execute('SELECT autor_id FROM noticia WHERE id=%s', (noticia_id,))
        fila_n = cur.fetchone()
        if not fila_n:
            cur.close()
            conexion.close()
            flash('Noticia asociada no encontrada', 'error')
            return redirect(request.referrer or url_for('noticias_lista'))

        autor_id_db = fila_n['autor_id']
        if autor_id_db != usuario['id']:
            cur.close()
            conexion.close()
            return render_template(
                'error.html',
                mensaje='Acceso denegado: solo el autor puede eliminar adjuntos de esta noticia'
            ), 403

        # ✅ Borrar archivo en disco si aplica
        if modo == 'disco' and nombre_guardado:
            ruta = os.path.join(DIRECTORIO_ARCHIVOS, nombre_guardado)
            try:
                if os.path.exists(ruta):
                    os.remove(ruta)
            except Exception as e:
                print(f"[adjunto_eliminar] fallo borrando archivo en disco: {e}")

        # ✅ Eliminar registro del adjunto
        cur.execute('DELETE FROM adjunto WHERE id=%s', (adjunto_id,))
        conexion.commit()

    except Exception as e:
        conexion.rollback()
        cur.close()
        conexion.close()
        print(f"[adjunto_eliminar] excepción: {e}")
        return render_template('error.html', mensaje='Error al eliminar adjunto'), 500

    # ✅ Cerrar conexiones y redirigir
    cur.close()
    conexion.close()
    flash('Adjunto eliminado correctamente', 'success')
    return redirect(url_for('noticias_editar', noticia_id=noticia_id))



# servir imagen inline desde BD
# servir imagen inline desde BD
@aplicacion.route('/adjuntos/<int:adjunto_id>/inline')
def adjunto_inline(adjunto_id):
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))
    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT contenido_bytea, tipo_mime FROM adjunto WHERE id=%s AND modo_almacenamiento='bd'", (adjunto_id,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()
    if not fila:
        return render_template('error.html', mensaje='Adjunto no encontrado o no es imagen'), 404
    contenido_bytea = fila['contenido_bytea']
    tipo_mime = fila['tipo_mime']
    return Response(contenido_bytea, mimetype=tipo_mime, headers={'Content-Disposition': 'inline'})

# descargar adjunto (desde BD o disco)
@aplicacion.route('/adjuntos/<int:adjunto_id>/descargar')
def adjunto_descargar(adjunto_id):
    if not usuario_logueado():
        return redirect(url_for('iniciar_sesion'))

    conexion = obtener_conexion()
    cur = conexion.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT nombre_original, nombre_guardado, tipo_mime, modo_almacenamiento, contenido_bytea
        FROM adjunto
        WHERE id=%s
    """, (adjunto_id,))
    fila = cur.fetchone()
    cur.close()
    conexion.close()

    if not fila:
        return render_template('error.html', mensaje='Adjunto no encontrado'), 404

    nombre_original = fila['nombre_original']
    nombre_guardado = fila['nombre_guardado']
    tipo_mime = fila['tipo_mime']
    modo = fila['modo_almacenamiento']
    contenido = fila['contenido_bytea']

    # Codificar para navegadores que no manejan bien caracteres especiales
    nombre_seguro = secure_filename(nombre_original)
    nombre_utf8 = quote(nombre_original)

    if modo == 'bd' and contenido is not None:
        headers = {
            'Content-Disposition': f"attachment; filename=\"{nombre_seguro}\"; filename*=UTF-8''{nombre_utf8}"
        }
        return Response(contenido, mimetype=tipo_mime, headers=headers)

    if modo == 'disco' and nombre_guardado:
        return send_from_directory(
            DIRECTORIO_ARCHIVOS,
            nombre_guardado,
            as_attachment=True,
            download_name=nombre_original
        )

    return render_template('error.html', mensaje='No se puede servir el adjunto'), 500

# -------------- envío de correos --------------

def enviar_notificacion_correo(titulo, cuerpo, noticia_id):
    try:
        # Obtener todos los correos
        conexion = obtener_conexion()
        cursor = conexion.cursor()
        cursor.execute("SELECT correo FROM usuario")
        destinatarios = [fila[0] for fila in cursor.fetchall()]
        cursor.close()
        conexion.close()

        if not destinatarios:
            print("❌ No hay destinatarios válidos")
            return

        # Crear el mensaje
        enlace = f"https://notificaciones-insedomau.onrender.com/noticias/{noticia_id}"
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


# -------------- ejecutar --------------
if __name__ == '__main__':
    aplicacion.run(host="0.0.0.0", port=5000, debug=True)