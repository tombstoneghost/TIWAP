# Imports
import sqlite3
from hashlib import md5


class DBManager:
    def __init__(self):
        # Initialize Database
        self.conn = None
        self.cur = None
        self.create_db_connection()

    def create_db_connection(self):
        self.conn = sqlite3.connect('TIWAP.db', check_same_thread=False)
        self.cur = self.conn.cursor()

    def get_db_connection(self):
        return self.conn

    def close_db_connection(self):
        return self.cur.close()

    def commit_db(self):
        return self.conn.commit()

    def check_user(self, username):
        self.create_db_connection()
        result = self.cur.execute("SELECT username FROM users WHERE username = ?", (username,))

        if type(result) != 'NoneType':
            if self.cur.fetchone() is not None:
                self.close_db_connection()
                return True

        self.close_db_connection()
        return False

    def check_login(self, username, password):
        self.create_db_connection()
        result = self.cur.execute("SELECT username, password FROM users WHERE username = ?", (username,))

        if type(result) != 'NoneType':
            data = self.cur.fetchone()
            self.close_db_connection()
            password_db = data[1]

            password = md5(bytes(password, encoding='utf-8')).hexdigest()

            # Check Passwords
            if password == password_db:
                return True

    def update_pass(self, username, password):
        self.create_db_connection()
        password = md5(bytes(password, encoding='utf-8')).hexdigest()
        result = self.cur.execute("UPDATE users SET password= ? WHERE username= ?", (password, username))
        
        if result:
            return True
        return False

    def get_comments(self):
        self.create_db_connection()
        result = self.cur.execute("SELECT comment FROM comments")

        if type(result) != 'NoneType':
            data = self.cur.fetchall()
            self.close_db_connection()
            return data

    def save_comment(self, comment):
        self.create_db_connection()
        result = self.cur.execute('INSERT INTO comments VALUES(?)', (comment, ))
        self.close_db_connection()
        self.commit_db()

        if result:
            return True

        return False

    def get_user_data(self, userid):
        self.create_db_connection()
        result = self.cur.execute('SELECT * FROM users WHERE userid = (?)', (userid, ))

        if type(result) != 'NoneType':
            data = self.cur.fetchone()
            self.close_db_connection()
            return data

    def get_names(self):
        self.create_db_connection()
        result = self.cur.execute("SELECT name from names")

        if type(result) != 'NoneType':
            data = self.cur.fetchall()
            self.close_db_connection()
            return data

    def save_name(self, name):
        self.create_db_connection()
        result = self.cur.execute("INSERT INTO names VALUES(?)", (str(name), ))
        self.close_db_connection()
        self.commit_db()

        if result:
            return True

        return False

    def reset_db(self):
        self.create_db_connection()
        with open('helper/sqlite_db_reset.txt') as f:
            contents = f.readlines()

        for content in contents:
            self.cur.execute(content)

        self.close_db_connection()
        self.commit_db()
