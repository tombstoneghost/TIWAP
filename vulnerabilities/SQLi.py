# Imports
import sqlite3
from helper.db_manager import DBManager


# Global Objects
dbmanager = DBManager()


# SQL Injection - Low Function
def sqli_low(username, password):
    global dbmanager

    cur = dbmanager.get_db_connection().cursor()

    if dbmanager.check_user(username=username):
        return "User Exists"

    try:
        stmt = "SELECT * FROM users WHERE username='%s'" % (str(username))

        result = cur.execute(stmt)

    except sqlite3.OperationalError as e:
        return e

    return result.fetchall()


# Blind SQL Injection - Low Function
def blind_sqli_low(username, password):
    global dbmanager

    cur = dbmanager.get_db_connection().cursor()

    if dbmanager.check_user(username=username):
        return "User Exists"

    try:
        stmt = "SELECT * FROM users WHERE username='%s'" % (str(username))

        result = cur.execute(stmt)

    except sqlite3.OperationalError as e:
        return ""

    return result.fetchall()
