# Imports
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps
from helper.jwt import JWT
from helper.db_manager import DBManager
from helper.mongodb_manager import MongoDBManager
from vulnerabilities import SQLi

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'l0G1n_53cR37_k3y'

# JWT
jwt = JWT()
dbm = DBManager()
mongo_dbm = MongoDBManager()


@app.route('/')
def index():
    if session and session['logged_in']:
        return redirect(url_for('dashboard'))
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
@is_logged
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
    if len(request.form) < 1:
        return redirect(url_for('sql_injection_index'))

    username = request.form.get('username')
    password = request.form.get('password')

    sqli = SQLi

    result = sqli.sqli_low(username=username, password=password)

    return render_template('vulnerabilities/sql-injection.html', msg=result)


# Blind SQL Injection
# Index Page
@app.route('/blind-sql-injection')
@is_logged
def blind_sql_injection_index():
    return render_template('vulnerabilities/blind-sql-injection.html')


# Route for Low Vulnerability
@app.route('/blind-injection-low', methods=['GET', 'POST'])
@is_logged
def blind_sql_injection_low():
    if len(request.form) < 1:
        return redirect(url_for('blind_sql_injection_index'))

    username = request.form.get('username')
    password = request.form.get('password')

    sqli = SQLi

    result = sqli.blind_sqli_low(username=username, password=password)

    return render_template('vulnerabilities/blind-sql-injection.html', msg=result)


# NoSQL Injection
# Index Page
@app.route('/no-sql-injection')
@is_logged
def no_sql_injection():
    data = mongo_dbm.get_data_all()

    return render_template('vulnerabilities/no-sql-injection.html', data=data)


# Route for Low Vulnerability
@app.route('/no-sql-injection-low', methods=['POST', 'GET'])
@is_logged
def no_sql_injection_low():
    if len(request.form) < 1:
        return redirect(url_for('no_sql_injection'))

    query = request.form.get('car')

    data = mongo_dbm.get_data_filtered(query)

    print(data)

    return render_template('vulnerabilities/no-sql-injection.html')


# Reflected XSS
# Index Page
@app.route('/reflected-xss')
@is_logged
def reflected_xss():
    return render_template('vulnerabilities/reflected-xss.html')


# Route for Low Vulnerability
@app.route('/reflected-xss-low', methods=['POST', 'GET'])
@is_logged
def reflected_xss_low():
    if len(request.form) < 1:
        return redirect(url_for('reflected_xss'))

    entry = request.form.get('input')

    msg = "Hi!" + entry

    return render_template('vulnerabilities/reflected-xss.html', msg=msg)


# Execute Main
if __name__ == '__main__':
    app.run()
