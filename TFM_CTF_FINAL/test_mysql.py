import mysql.connector

db_host = 'localhost'
db_user = 'root'
db_password = 'passwordtfm'
db_database = 'ctf'

try:
    connection = mysql.connector.connect(user=db_user, password=db_password, host=db_host, database=db_database)
    cursor = connection.cursor()
    cursor.execute("SELECT VERSION()")
    result = cursor.fetchone()
    print(f"Conectado a MySQL versión: {result[0]}")
    cursor.close()
    connection.close()
except mysql.connector.Error as e:
    print(f"Error al conectarse a MySQL: {e}")
