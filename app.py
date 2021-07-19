# Imports
from flask import Flask, render_template, request, session, redirect, url_for
from passlib.hash import sha256_crypt
from functools import wraps
from helper.jwt import JWT

import sqlite3


# Initialize Database
conn = sqlite3.connect('TIWAF.db', check_same_thread=False)
cur = conn.cursor()

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'l0G1n_53cR37_k3y'

# JWT
jwt = JWT()


@app.route('/')
def index():
    return render_template('index.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == '' and password == '':
        return render_template('index.html', msg='Fields Empty')

    result = cur.execute("SELECT username, password FROM users WHERE username = ?", (username, ))

    if type(result) != 'NoneType':
        data = cur.fetchone()
        password_db = data[1]

        # Check Passwords
        if sha256_crypt.verify(password, password_db):
            session['logged_in'] = True
            session['auth'] = jwt.encode_auth_token(username)

            return redirect(url_for('dashboard'))
        else:
            return render_template('index.html', msg='Invalid Credentials')
    else:
        return render_template('index.html', msg='Username not found')

    return render_template('index.html')


# Check if user is logged in
def is_logged(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('index'))

    return wrap


# Logout
@app.route('/logout')
def logout():
    session.clear()

    return redirect(url_for('index'))


# Dashboard
@app.route('/dashboard')
@is_logged
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run()
