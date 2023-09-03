from flask import Flask, render_template, request, redirect, \
    session, url_for, flash
import mysql.connector
import time
import re
from bleach.sanitizer import Cleaner
import os
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import secrets




app = Flask(__name__, template_folder='templates')
app.secret_key = 'clave_secreta_tfm'
comments = []

# Configuración de la conexión a la base de datos
db_host = 'localhost'
db_user = 'root'
db_password = 'passwordtfm'
db_database = 'ctf'


@app.route('/')
def inicio():
    # Establece el reto inicial solo si no está ya configurado
    if 'reto_actual' not in session:
        session['reto_actual'] = 1
    return render_template('inicio.html')


# Función para verificar si el usuario puede acceder a un reto específico
def verificar_acceso(num_reto):
    if 'reto_actual' not in session or num_reto > session['reto_actual']:
        return False
    return True

# Retos SQLi
@app.route('/reto1', methods=['GET', 'POST'])
def reto1():
    # Verificación de acceso al reto (definida previamente en una función separada).
    if not verificar_acceso(1):
        return "Acceso denegado", 403

    error = None
    if request.method == 'POST':
        # Recolección de las entradas del usuario desde el formulario.
        username = request.form['username']
        password = request.form['password']
        # Conexión a la base de datos usando las credenciales definidas globalmente.
        connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
        cursor = connection.cursor()

        # Bloque try para manejar posibles errores de SQL.
        try:
            # Construcción de la consulta SQL con las entradas del usuario sin validar ni escapar.
            # Esta es la línea vulnerable a la Inyección SQL.
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}';"

            # Ejecución de la consulta SQL.
            cursor.execute(query)
            # Recuperación de los resultados de la consulta. Si hay resultados, se avanza al siguiente reto.
            result = cursor.fetchall()
            if result:
                # Avanza al siguiente reto
                session['reto_actual'] = 2
                return redirect('/reto2')
        except mysql.connector.Error:
            # Manejo de errores de SQL, proporcionando un mensaje genérico de error al usuario
            # para no dar información detallada.
            error = "Ha ocurrido un error. Por favor, inténtalo de nuevo."

        # Cierre de la conexión con la base de datos.
        cursor.close()
        connection.close()

    # Renderización de la página HTML del reto, pasando el mensaje de error si hay uno.
    return render_template('reto1.html', error=error)

@app.route('/reto2', methods=['GET', 'POST'])
def reto2():

    def is_payload_prohibited(input_string):
        # Convertir la cadena a minúsculas y eliminar los espacios adicionales.
        cleaned_input = ''.join(input_string.lower().split())

        # Lista de patrones prohibidos.
        prohibited_patterns = ['union', 'or1=', 'ortrue', 'ora=', "or'1'=", "or'a'="]

        for pattern in prohibited_patterns:
            if pattern in cleaned_input:
                return True

        return False

    # Verificación de acceso al reto.
    if not verificar_acceso(2):
        return "Acceso denegado", 403

    # Inicialización de la variable para el mensaje.
    mensaje = None

    # Verificación de si la petición es un POST.
    if request.method == 'POST':
        # Recolección de las entradas del usuario.
        username = request.form['username']
        password = request.form['password']

        # Verifica si el payload está prohibido antes de proceder.
        if is_payload_prohibited(username) or is_payload_prohibited(password):
            mensaje = "Este payload está prohibido."
        else:
            # Conexión a la base de datos.
            connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
            cursor = connection.cursor()
            # Construcción de la consulta SQL con las entradas del usuario.
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

            try:
                # Ejecutar la query proporcionada por el usuario.
                cursor.execute(query)
                results = cursor.fetchall()

            except mysql.connector.Error as e:
                error_message = str(e)

                # Verificar si el mensaje de error contiene "MySQL".
                if "MySQL" in error_message:
                    session['reto_actual'] = 3
                    mensaje = f"¡Felicidades! Has descubierto que la base de datos es MySQL a través del error: {error_message}"
                else:
                    mensaje = "Inténtalo de nuevo. La clave está en el error."

            finally:
                cursor.close()
                connection.close()

    return render_template('reto2.html', mensaje=mensaje)

@app.route('/reto3', methods=['GET', 'POST'])
def reto3():
    # Verificación de acceso al reto
    if not verificar_acceso(3):
        return "Acceso denegado", 403

    # Inicialización de las variables
    mensaje = None
    tablas_descubiertas = False
    tablas = []
    nombre_database = ""

    # Verificación de si la petición es un POST
    if request.method == 'POST':
        consulta = request.form['consulta']

        # Conexión a la base de datos
        connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
        cursor = connection.cursor()

        try:
            # Verificar si la consulta incluye 'UNION'
            if 'UNION' not in consulta.upper():
                raise ValueError("No estás usando el payload correcto")

            # Construcción y ejecución de la consulta SQL con las entradas del usuario
            query = f"SELECT * FROM users WHERE username = '{consulta}'"
            cursor.execute(query)
            results = cursor.fetchall()

            # Consulta para extraer el nombre de la base de datos de la aplicación
            query_nombre_database = "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'ctf'"
            cursor.execute(query_nombre_database)
            # Extraer el nombre de la base de datos
            result = cursor.fetchone()
            if result:
                nombre_database = result[0]

            # Consulta para buscar las tablas de la BD 'ctf'
            query_tablas = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'ctf'"
            cursor.execute(query_tablas)
            # Extraer los nombres de las tablas
            tablas = [row[0] for row in cursor]

            # Verificar si alguna de las tablas está presente en los resultados
            tablas_encontradas = [table for table in tablas if any(table in result for result in results)]

            if nombre_database in ''.join([str(r) for r in results]):
                mensaje = f"¡Bien Hecho! Has descubierto que el nombre de la base de datos es '{nombre_database}'. Ahora, ¿puedes descubrir las tablas?"

            elif tablas_encontradas and 'ctf' in consulta:
                tablas_descubiertas = True
                # Avanza al siguiente reto
                session['reto_actual'] = 4
                mensaje = f"Felicidades, has descubierto las tablas: {', '.join(tablas_encontradas)}."

            elif tablas_encontradas:
                tablas_descubiertas = True
                mensaje = f"Casi correcto... pero no has especificado el nombre de la base de datos, la conoces?¿"

            else:
                mensaje = "Inténtalo de nuevo"

        except ValueError as ve:
            mensaje = str(ve)

        except mysql.connector.Error as e:
            # Manejo de errores de SQL
            mensaje = f"Parece que tienes el siguiente error: {str(e)}"

        # Cierre de la conexión con la base de datos
        cursor.close()
        connection.close()

    # Renderización de la página HTML del reto
    return render_template('reto3.html', mensaje=mensaje, tablas_descubiertas=tablas_descubiertas, tablas=tablas, nombre_database=nombre_database)

@app.route('/reto4', methods=['GET'])
def reto4():
    # Verificación de acceso al reto
    if not verificar_acceso(4):
        return "Acceso denegado", 403

    # Mensaje inicial para el usuario
    mensaje = "Debes manipular esta web para pasar al siguiente reto."
    reto_resuelto = False

    # Obtención del parámetro 'users' de la URL, parámetro no modificable en el navegador
    users_parametro = request.args.get('users')

    # Comprobación de sí el parámetro 'users' es igual a 'admin'
    if users_parametro == 'admin':
        # Conexión a la base de datos
        connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
        cursor = connection.cursor()
        try:
            # Consulta SQL para obtener el usuario 'admin'
            query = "SELECT * FROM users WHERE username = 'admin'"
            cursor.execute(query)
            resultado = cursor.fetchone()

            # Comprobación de si el usuario 'admin' existe
            if resultado:
                # Avance al siguiente reto
                session['reto_actual'] = 5
                mensaje = "¡Felicidades! Has resuelto el reto."
                reto_resuelto = True

        except mysql.connector.Error as e:
            # Manejo de errores de SQL
            mensaje = f"Has inducido el siguiente error: {str(e)}"

        # Cierre de la conexión con la base de datos
        cursor.close()
        connection.close()

    # Renderización de la página HTML del reto
    return render_template('reto4.html', mensaje=mensaje, reto_resuelto=reto_resuelto)

@app.route('/reto5', methods=['GET', 'POST'])
def reto5():
    # Verificación de acceso al reto
    if not verificar_acceso(5):
        return "Acceso denegado", 403

    # Inicialización de variables de control y mensajes
    mensaje = None
    consulta_correcta = False

    # Verificación de método POST
    if request.method == 'POST':
        consulta = request.form['consulta']
        # Conexión a la base de datos
        connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
        cursor = connection.cursor()

        try:
            # Medición del tiempo de inicio de la consulta
            start_time = time.time()
            # Creación y ejecución de la consulta SQL
            query = f"SELECT id FROM users WHERE username = '{consulta}'"
            cursor.execute(query)
            resultado = cursor.fetchone()

            # Medición del tiempo final de la consulta
            end_time = time.time()
            elapsed_time = end_time - start_time

            # Verificación del resultado y tiempo de ejecución (el tiempo cuenta desde que se lanza la petición)
            if resultado and elapsed_time > 5:
                consulta_correcta = True
                # Avanza al siguiente reto
                session['reto_actual'] = 6
                mensaje = f"Has descubierto que el id del usuario {consulta} es {resultado[0]}. ¡Bien hecho!"

        # Manejo de errores de SQL
        except mysql.connector.Error as e:
            mensaje = f"Has inducido el siguiente error: {str(e)}"

        # Cierre de la conexión con la base de datos
        cursor.close()
        connection.close()

    # Renderización de la página HTML del reto
    return render_template('reto5.html', mensaje=mensaje, consulta_correcta=consulta_correcta)

# Retos XSS
@app.route('/reto6', methods=['GET', 'POST'])
def reto6():
    # Verificación de acceso al reto
    if not verificar_acceso(6):
        return "Acceso denegado", 403

    # Inicializar la variable que mostrará un mensaje al usuario
    mensaje = None

    # Inicializar la consulta con un valor vacío
    search_query = ""

    # Comprobar si el método de la solicitud es POST
    if request.method == 'POST':
        # Obtener el valor de la entrada 'query' del formulario
        search_query = request.form.get('query', '')

        # Comprobar si el usuario ingresó el script correcto
        if "<script>alert('hackeado')</script>" in search_query:
            session['reto_actual'] = 7
            mensaje = "¡Felicidades! Reto superado."

        # Comprobar si el usuario no ha usado la etiqueta <script>
        elif "<script>" not in search_query:
            mensaje = "La <etiqueta> para superar el reto es bastante fácil"

    # Renderizar la plantilla con los datos correspondientes
    return render_template('reto6.html', query=search_query, mensaje=mensaje)

@app.route('/reto7', methods=['GET', 'POST'])
def reto7():
    # Verificación de acceso al reto
    if not verificar_acceso(7):
        return "Acceso denegado", 403

    # Inicializar la variable que mostrará un mensaje al usuario
    mensaje = None

    # Inicializar la consulta con un valor vacío
    search_query = ""

    # Comprobar si el método de la solicitud es POST
    if request.method == 'POST':
        # Obtener el valor de la entrada 'query' del formulario
        search_query = request.form.get('query', '')

        # Comprobar si el usuario intenta etiquetas conocidas, pero que no hacen superar el reto.
        # Se omite deliberadamente svg y onload
        if any(tag in search_query for tag in ["img", "script", "div", "onerror", "onmouseover"]):
            mensaje = "Ese no es el método que te hará superar el reto."

        # Comprobar si el payload contiene la palabra "hackeado"
        # y usa la etiqueta <svg para superar el reto
        elif "hackeado" in search_query and "<svg onload" in search_query:
            session['reto_actual'] = 8
            mensaje = "¡Felicidades! Reto superado."
        else:
            mensaje = "Inténtalo de nuevo"

    # Renderizar la plantilla con los datos correspondientes
    return render_template('reto7.html', query=search_query, mensaje=mensaje)

@app.route('/reto8', methods=['GET', 'POST'])
def reto8():
    # Verificación de acceso al reto
    if not verificar_acceso(8):
        return "Acceso denegado", 403

    mensaje = None

    # Configuración para Bleach
    cleaner = Cleaner(tags=['a'],
                      attributes={'a': ['href']},
                      protocols=['http', 'https', 'javascript'],
                      strip=True)

    if request.method == 'POST':
        user_comment = request.form.get('comment', '')
        cleaned_comment = cleaner.clean(user_comment)
        comments.append(cleaned_comment)

        # Expresión regular para verificar el payload con cualquier contenido.
        pattern = r'<a href="javascript:alert\(\'hackeado\'\)">.+</a>'

        if re.search(pattern, cleaned_comment):
            session['reto_actual'] = 9
            mensaje = "¡Felicidades! Reto superado."
        else:
            mensaje = "Inténtalo de nuevo."

    return render_template('reto8.html', comments=comments, mensaje=mensaje)

@app.route('/reto9', methods=['GET', 'POST'])
def reto9():
    # Verificación de acceso al reto
    if not verificar_acceso(9):
        return "Acceso denegado", 403

    # Limpiar los comentarios del reto anterior al comienzo de la función
    comments.clear()
    mensaje = ""

    # Configuración de Bleach
    cleaner = Cleaner(
        tags=['b', 'i', 'u', 'a', 'span', 'div', 'style'],
        attributes={'a': ['href', 'title', 'name'], 'span': ['style'], 'div': ['style'], 'style': []},
        protocols=['http', 'https'],
        strip=True
    )

    if request.method == 'POST':
        user_comment = request.form.get('comment', '')

        # Verifica si el comentario contiene la estructura de una etiqueta style con una propiedad background-image
        pattern = re.compile(r"<style>\s*body\s*{\s*background-image\s*:\s*url\(['\"]?(.*?)['\"]?\)\s*;\s*}</style>", re.I)
        match = pattern.search(user_comment)

        if match:
            url = match.group(1)
            # Comprueba si la URL está presente dentro de la propiedad background-image
            if url:
                comments.append(user_comment)
                session['reto_actual'] = 10
                mensaje = "¡Felicidades! Reto superado."

            else:
                mensaje = "Inténtalo de nuevo."
        else:
            mensaje = "Inténtalo de nuevo."

    return render_template('reto9.html', comments=comments, mensaje=mensaje)

@app.route('/reto10', methods=['GET', 'POST'])
def reto10():
    # Verificación de acceso al reto
    if not verificar_acceso(10):
        return "Acceso denegado", 403

    # Limpiar los comentarios del reto anterior al comienzo de la función
    comments.clear()
    mensaje = ""

    if request.method == 'POST':
        user_comment = request.form.get('comment', '')

        # No sanitizar el comentario
        comments.append(user_comment)

        # Verificar la presencia del evento onmouseover
        if "onmouseover" in user_comment:
            session['reto_actual'] = 11
            mensaje = "¡Felicidades! Reto superado."
        else:
            mensaje = "Inténtalo de nuevo."

    return render_template('reto10.html', comments=comments, mensaje=mensaje)

@app.route('/reto11', methods=['GET', 'POST'])
def reto11():
    # Verificación de acceso al reto
    if not verificar_acceso(11):
        return "Acceso denegado", 403

    folder = 'static'
    extensions = {'jpg'}
    app.config['folder'] = folder

    def allowed_file(filename):
        # Comprobar si el archivo tiene una extensión permitida
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

    mensaje = ""
    custom_style = ""

    if 'style' in request.form:
        custom_style = request.form['style']

        # Extraer URL de fuente del CSS
        import re
        font_url_match = re.search(r'src: url\("(.+?)"\)', custom_style)
        if font_url_match:
            font_path = font_url_match.group(1)
            # Convertir la URL en una ruta relativa del sistema
            local_path = urlparse(font_path).path
            print("Local Path:", local_path)

            # Construir el path absoluto del archivo en el sistema
            full_path = os.path.join(app.root_path, local_path.lstrip("/"))

            # Comprobar que el path comienza con la carpeta 'static' y que el archivo realmente existe
            if full_path.startswith(os.path.join(app.root_path, 'static')) and os.path.exists(full_path):
                session['reto_actual'] = 12
                mensaje = "Felicidades, has superado el reto!"
            else:
                mensaje = "Inténtalo de nuevo."

    if 'image' in request.files:
        file = request.files['image']
        # Comprobar que el archivo sea válido y esté permitido
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Construir el path donde se guardará el archivo
            filepath = os.path.join(app.config['folder'], filename)
            file.save(filepath)
            mensaje = "Imagen (u otro archivo) cargada correctamente."

    return render_template('reto11.html', mensaje=mensaje, custom_style=custom_style)

# Retos CSRF

# Usuarios retos CSRF
usersCSRF = {
    "user": "passwd",
    'user1': 'password1',
    'user2': 'password2',
}

@app.route('/reto12login', methods=['GET', 'POST'])
def reto12login():

    # Verificación de acceso al reto.
    if session.get('reto_actual', 1) < 12:
        return "Acceso denegado", 403

        # Maneja el inicio de sesión
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Verificar si el usuario y la contraseña ingresados coinciden con los del diccionario
        if usersCSRF.get(username) == password:
            session['reto_actual'] = 13
            # Si es correcto, guardar el nombre de usuario en la sesión y redirige al reto 12
            session['username_retosCSRF'] = username
            return redirect(url_for('reto12'))
        else:
            # Si no es correcto, mostrar un mensaje de error
            flash("Usuario o contraseña incorrectos")

    return render_template('reto12login.html')

@app.route('/reto12', methods=['GET', 'POST'])
def reto12():

    # Verificación de acceso al reto12.
    if not session.get('username_retosCSRF') or session.get('reto_actual', 1) < 13:
        return redirect(url_for('reto12login'))

    mensaje = ""
    reto_superado = False

    if request.method == "POST":
        source = request.form.get("source")
        new_username = request.form.get("new_username")

        old_username = session["username_retosCSRF"]
        # Asegurarse que el antiguo usuario exista en el diccionario
        if old_username in usersCSRF:
            # Actualizar el diccionario con el nuevo nombre de usuario
            usersCSRF[new_username] = usersCSRF.pop(old_username)
            # Actualizar la sesión con el nuevo nombre de usuario
            session["username_retosCSRF"] = new_username
            mensaje = "¡Nombre de usuario cambiado!"

            # Si la fuente no es "legitimo" y el nombre de usuario es "hacker", validamos el reto.
            if source != "legitimo" and new_username == "hacker":
                session['reto_actual'] = 14
                reto_superado = True
                mensaje = "¡Felicidades! Has superado el reto."

    return render_template('reto12.html', mensaje=mensaje, username=session["username_retosCSRF"], reto_superado=reto_superado)

# Saldo actual cuenta destino - Reto 13
saldo_destino = 0

@app.route('/reto13', methods=['GET', 'POST'])
def reto13():
    # Verificación de acceso al reto
    if not verificar_acceso(14):
        return "Acceso denegado", 403

    global saldo_destino
    mensaje = ""
    reto_superado = False

    if request.method == "POST":
        cuenta_destino = request.form.get("cuenta_destino")
        cantidad = request.form.get("cantidad")
        source = request.form.get("source")

        # Verificar si la fuente del request no es "legitimo" y si los datos enviados son correctos
        if source != "legitimo" and cuenta_destino == "IBAN1234567" and cantidad == "1000":
            # Actualizar el saldo al transferir los fondos
            saldo_destino += 1000
            reto_superado = True
            session['reto_actual'] = 15
            mensaje = "Fondos transferidos correctamente. ¡Felicidades! Has superado el reto."

        elif source == "legitimo" and cuenta_destino != "IBAN1234567" and cantidad != "1000":
            mensaje = "Inténtalo de nuevo."
        else:
            mensaje = "Debes enviar la trasferencia desde otro medio"

    return render_template('reto13.html', mensaje=mensaje, username=session["username_retosCSRF"],
                           reto_superado=reto_superado, saldo=saldo_destino)

@app.route('/reto14', methods=['GET', 'POST'])
def reto14():

    # Verificación de acceso al reto
    if not verificar_acceso(15):
        return "Acceso denegado", 403

    def generate_csrf_token():
        return secrets.token_hex(16)

    global saldo_destino
    mensaje = ""
    reto_superado = False

    if request.method == 'POST':
        cuenta_destino = request.form.get('cuenta_destino')
        cantidad = request.form.get('cantidad')
        csrf_token = request.form.get('csrf_token')
        provided_csrf_token = request.form.get('provided_csrf_token')
        source = request.form.get("source")
        concepto = request.form.get('concepto')

        session['last_concept'] = concepto

        if source != "legitimo" and cuenta_destino == "IBAN1234567" and cantidad == "1000" and provided_csrf_token == session.get('csrf_token'):
            session['reto_actual'] = 16
            mensaje = "Fondos transferidos correctamente. ¡Felicidades! Has superado el reto."
            saldo_destino += 1000
            reto_superado = True

        elif csrf_token != session.get('csrf_token'):
            mensaje = "Token CSRF inválido."
        else:
            mensaje = "Debes realizar la transferencia por otro medio"

    if not session.get('csrf_token'):
        session['csrf_token'] = generate_csrf_token()

    concepto = session.get('last_concept', '')

    return render_template('reto14.html_', mensaje=mensaje, csrf_token=session.get('csrf_token'), concepto=concepto, reto_superado=reto_superado, saldo=saldo_destino)

# RETO FINAL SQLi + XSS + CSRF

# Ruta para gestionar el inicio de sesión del reto 15
@app.route('/reto15login', methods=['GET', 'POST'])
def reto15login():

    # Verificación de acceso al reto
    if not verificar_acceso(16):
        return "Acceso denegado", 403

    mensaje = None

    # Establecer conexión con la base de datos
    connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
    cursor = connection.cursor()

    # Si la solicitud es un POST, se intentará autenticar al usuario
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Se realiza una consulta parametrizada para prevenir inyección SQL
        cursor.execute("SELECT password, role FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        # Si el usuario existe
        if user:
            stored_password, role = user
            # Se verifica que la contraseña proporcionada coincida con la almacenada
            if password == stored_password:
                session['reto_actual'] = 17
                # Se gestionan distintos escenarios dependiendo del nombre de usuario y el rol
                if username == "user" and role == 'usuario':
                    return redirect(url_for('reto15'))
                elif username == "user" and role == 'superadmin':
                    return render_template('reto15login.html', mensaje="¡FELICIDADES!.¡¡¡HAS SUPERADO EL RETO FINAL!!!.", success=True)
                elif username == "admin" and role == 'superadmin':
                    return redirect(url_for('reto15admin'))

        mensaje = "Inténtalo de nuevo"

    # Si la autenticación falla o es un GET, se muestra la página de inicio de sesión
    return render_template('reto15login.html', mensaje=mensaje)

# Ruta para cerrar sesión
@app.route('/reto15logout')
def reto15logout():
    # Restablecer el reto_actual a 16 en lugar de borrar toda la sesión
    session['reto_actual'] = 16
    return redirect(url_for('reto15login'))

# Ruta para gestionar el reto 15
@app.route('/reto15', methods=['GET', 'POST'])
def reto15():
    # Verificar si el usuario tiene acceso al reto 17
    if not verificar_acceso(17):
        return "Acceso denegado", 403

    global connection
    mensaje = ""
    session['reto_actual'] = 18

    # Si la solicitud es un POST, se maneja la acción "publicar"
    if request.method == 'POST':
        accion = request.form.get('accion')
        if accion == "publicar":
            msg = request.form.get('mensaje')

            try:
                # Establecer conexión con la base de datos y guardar el mensaje
                connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
                cursor = connection.cursor()
                # Inyección SQL potencialmente peligrosa
                query = f"INSERT INTO mensajes (user_id, contenido) VALUES (32, '{msg}')"
                cursor.execute(query)
                connection.commit()
                cursor.close()

                mensaje = "Mensaje publicado con éxito"
            except Exception as e:
                mensaje = str(e)
            finally:
                connection.close()

    return render_template('reto15.html', mensaje=mensaje)

# Ruta para gestionar la vista de administrador del reto 15
@app.route('/reto15admin', methods=['GET', 'POST'])
def reto15admin():
    # Establecer conexión con la base de datos y recuperar todos los mensajes
    connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
    cursor = connection.cursor()
    cursor.execute(f"SELECT user_id, contenido FROM mensajes;")
    mensajes = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('reto15admin.html', mensajes=mensajes)

# Ruta para eliminar mensajes
@app.route('/reto15delete', methods=['GET'])
def reto15delete():
    mensaje_id = request.args.get('mensaje_id')
    if not mensaje_id:
        return "ID del mensaje no proporcionado", 400

    # Establecer conexión con la base de datos y eliminar el mensaje con el ID proporcionado
    connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
    cursor = connection.cursor()
    try:
        cursor.execute(f"DELETE FROM mensajes WHERE mensaje_id = {mensaje_id}")
        connection.commit()
    except mysql.connector.Error as e:
        return str(e), 500
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('reto15admin'))

# Ruta para promover usuarios a 'superadmin'
@app.route('/reto15promote', methods=['POST'])
def promote_user():
    user_id = request.form.get('user_id')
    new_role = request.form.get('new_role')

    # Si el nuevo rol es 'superadmin'
    if new_role == "superadmin":
        # Establecer conexión con la base de datos y actualizar el rol del usuario
        connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
        cursor = connection.cursor()
        try:
            update_query = f"UPDATE users SET role='superadmin' WHERE id={user_id}"
            cursor.execute(update_query)
            connection.commit()

            return "Usuario promovido a superadmin", 200
        except mysql.connector.Error as e:
            return str(e), 500
        finally:
            cursor.close()
            connection.close()

    return "Operación no permitida", 403


# FIN DEL CTF

if __name__ == '__main__':
    app.run(debug=True, port=7777)


