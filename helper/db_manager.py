# Imports
import sqlite3
from passlib.hash import sha256_crypt


class DBManager:
    def __init__(self):
        # Initialize Database
        self.conn = sqlite3.connect('TIWAF.db', check_same_thread=False)
        self.cur = self.conn.cursor()

    def check_login(self, username, password):
        result = self.cur.execute("SELECT username, password FROM users WHERE username = ?", (username,))

        if type(result) != 'NoneType':
            data = self.cur.fetchone()
            password_db = data[1]

            # Check Passwords
            if sha256_crypt.verify(password, password_db):
                return True
