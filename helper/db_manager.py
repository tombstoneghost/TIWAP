# Imports
import sqlite3
from hashlib import md5


class DBManager:
    def __init__(self):
        # Initialize Database
        self.conn = sqlite3.connect('TIWAF.db', check_same_thread=False)
        self.cur = self.conn.cursor()

    def get_db_connection(self):
        return self.conn

    def check_user(self, username):
        result = self.cur.execute("SELECT username FROM users WHERE username = ?", (username,))

        if type(result) != 'NoneType':
            if self.cur.fetchone() is not None:
                return True

        return False

    def check_login(self, username, password):
        result = self.cur.execute("SELECT username, password FROM users WHERE username = ?", (username,))

        if type(result) != 'NoneType':
            data = self.cur.fetchone()
            password_db = data[1]

            password = md5(bytes(password, encoding='utf-8')).hexdigest()

            # Check Passwords
            if password == password_db:
                return True

    def get_comments(self):
        result = self.cur.execute("SELECT comment FROM comments")

        if type(result) != 'NoneType':
            data = self.cur.fetchall()

            return data

    def save_comment(self, comment):
        result = self.cur.execute('INSERT INTO comments VALUES(?)', (comment, ))

        if result:
            return True

        return False

    def get_user_data(self, userid):
        result = self.cur.execute('SELECT * FROM users WHERE userid = (?)', (userid, ))

        if type(result) != 'NoneType':
            data = self.cur.fetchone()

            return data
