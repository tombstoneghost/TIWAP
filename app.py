# Imports
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps
from helper.jwt import JWT
from helper.db_manager import DBManager
from vulnerabilities import SQLi

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'l0G1n_53cR37_k3y'

# JWT
jwt = JWT()
dbm = DBManager()


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

    if dbm.check_login(username=username, password=password):
        session['logged_in'] = True
        session['auth'] = jwt.encode_auth_token(username)

        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html', msg='Invalid Credentials')

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


# SQL Injection
# Index Page
@app.route('/sql-injection')
@is_logged
def sql_injection_index():
    return render_template('vulnerabilities/sql-injection.html')


# Route for Low Vulnerability
@app.route('/injection-low', methods=['GET', 'POST'])
@is_logged
def sql_injection_low():
    username = request.form.get('username')
    password = request.form.get('password')

    sqli = SQLi

    result = sqli.sqli_low(username=username, password=password)

    return render_template('vulnerabilities/sql-injection.html', msg=result)


# Execute Main
if __name__ == '__main__':
    app.run()
