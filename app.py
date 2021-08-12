# Imports
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps
from helper.jwt import JWT
from helper.db_manager import DBManager
from helper.mongodb_manager import MongoDBManager
from vulnerabilities import SQLi
import os

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
@app.route('/login', methods=['POST'])
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
@app.route('/injection-low', methods=['POST'])
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
@app.route('/blind-injection-low', methods=['POST'])
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
@app.route('/no-sql-injection-low', methods=['POST'])
@is_logged
def no_sql_injection_low():
    if len(request.form) < 1:
        return redirect(url_for('no_sql_injection'))

    query = request.form.get('car')

    data = mongo_dbm.get_data_filtered(query)

    print(data)

    return render_template('vulnerabilities/no-sql-injection.html')


# Sensitive Data Exposure
# Index Page
@app.route('/sensitive-data-exposure')
@is_logged
def sensitive_data_exposure():
    return render_template('vulnerabilities/sensitive-data-exposure.html')


# Route for Low Vulnerability - User
@app.route('/sensitive-data-exposure/user')
@is_logged
def sensitive_data_exposure_low_user():
    user_id = request.args.get('userid')

    if int(user_id) == 1:
        user_id = 2

    data = dbm.get_user_data(userid=user_id)

    return render_template('vulnerabilities/sensitive-data-exposure.html', data=data)


# Route for Low Vulnerability - Admin
@app.route('/sensitive-data-exposure/admin/')
@is_logged
def sensitive_data_exposure_low_admin():
    user_id = request.args.get('userid')

    if int(user_id) != 1:
        return render_template('vulnerabilities/sensitive-data-exposure.html', msg="Invalid Admin ID")

    data = dbm.get_user_data(userid=user_id)

    return render_template('vulnerabilities/sensitive-data-exposure.html', data=data)


# Route for Low Vulnerability - Admin
@app.route('/sensitive-data-exposure/admin/config')
@is_logged
def sensitive_data_exposure_low_admin_config():
    user_id = request.args.get('userid')

    if int(user_id) != 1:
        return render_template('vulnerabilities/sensitive-data-exposure.html', msg="Invalid Admin ID")

    msg = "Here are the credentials for dev\n dev-user : BSYpUzIU0yDvvJ3"

    return render_template('vulnerabilities/sensitive-data-exposure.html', msg=msg)


# Reflected XSS
# Index Page
@app.route('/reflected-xss')
@is_logged
def reflected_xss():
    return render_template('vulnerabilities/reflected-xss.html')


# Route for Low Vulnerability
@app.route('/reflected-xss-low', methods=['POST'])
@is_logged
def reflected_xss_low():
    if len(request.form) < 1:
        return redirect(url_for('reflected_xss'))

    entry = request.form.get('input')

    msg = "Hi, " + entry

    return render_template('vulnerabilities/reflected-xss.html', msg=msg)


# Stored XSS
# Index Page
@app.route('/stored-xss')
@is_logged
def stored_xss():
    data = dbm.get_comments()

    return render_template('vulnerabilities/stored-xss.html', data=data)


# Route for Low Vulnerability
@app.route('/stored-xss-low', methods=['POST'])
@is_logged
def stored_xss_low():
    if len(request.form) < 1:
        return redirect(url_for('stored_xss'))

    comment = request.form.get('input')

    msg = ""

    if dbm.save_comment(comment=comment):
        msg = "Comment Saved"
    else:
        msg = "Unable to Save Comment"

    data = dbm.get_comments()

    return render_template('vulnerabilities/stored-xss.html', data=data, msg=msg)


# DOM Based XSS
# Index Page
@app.route('/dom-xss')
@is_logged
def dom_xss():
    return render_template('vulnerabilities/dom-xss.html')


# Route for Low Vulnerability
@app.route('/dome-xss-low', methods=['POST'])
@is_logged
def dom_xss_low():
    if len(request.form) < 1:
        return redirect(url_for('dom_xss'))

    entry = request.form.get('input')

    msg = "Hi, " + entry

    return render_template('vulnerabilities/dom-xss.html', msg=msg)


# Hardcoded Credentials
@app.route('/hardcoded-creds', methods=['POST', 'GET'])
@is_logged
def hardcoded_creds():
    username = request.form.get('username')
    password = request.form.get('password')

    msg = ""

    if username == 'dev-user' and password == 'BSYpUzIU0yDvvJ3':
        msg = "You are logged in!"

    return render_template('vulnerabilities/hardcoded-creds.html', msg=msg)

# Command Injection
@app.route('/cmd-injection')
@is_logged
def cmd_injection():
    return render_template('vulnerabilities/command_injection.html')

@app.route('/command-injection-low', methods=['POST'])
@is_logged
def cmd_injection_low():
    query = request.form.get('input')
    query = 'ping -c 4 ' + query
    stream = os.popen(query)
    output = stream.read()

    return render_template('vulnerabilities/command_injection.html', msg=output)
    

# Business Logic Flaw
@app.route('/business-logic')
@is_logged
def business_logic():
    return render_template('vulnerabilities/business-logic.html')


# Route for Low Vulnerability
@app.route('/business-logic-low', methods=['POST'])
@is_logged
def business_logic_low():
    
    username = request.form.get('username')
    password = request.form.get('password')
    result = "Incorrect Username or Password"
    if username=="adM1n1sTrat0R" and password=="123P4ssW0rd@@":
        result = "Logged in successfully as an ADMIN!!!"

    return render_template('vulnerabilities/business-logic.html', msg=result)


# Execute Main
if __name__ == '__main__':
    app.run()

