# Imports
import sqlite3
from helper.db_manager import DBManager


# Global Objects
dbmanager = DBManager()


# SQL Injection Class
def sqli_low(username, password):
    global dbmanager

    cur = dbmanager.get_db_connection().cursor()

    try:
        stmt = "SELECT * FROM users WHERE username='%s' and password='%s'" % (str(username), str(password))

        result = cur.execute(stmt)

    except sqlite3.OperationalError as e:
        return e

    return result.fetchall()
