# Imports
from flask import Flask, render_template, request, session, redirect, url_for
from functools import wraps
from helper import functioning
from helper.jwt import JWT
from helper.db_manager import DBManager
from helper.mongodb_manager import MongoDBManager
from vulnerabilities import SQLi, CommandInjection, BusinessLogic, XXE, XSS, BruteForce, NoSQL

import os

# Upload Folder Configuration
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads')

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'l0G1n_53cR37_k3y'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global Classes/Functions
jwt = JWT()
dbm = DBManager()
mongo_dbm = MongoDBManager()
funcs = functioning


'''
Difficulty      Levels
Low               0
Medium            1
Hard              2
'''


# Index
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
        session['level'] = 0

        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html', msg='Invalid Credentials')


# Decorator to Check if user is logged in
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


# Settings
@app.route('/settings', methods=['POST', 'GET'])
@is_logged
def settings():
    if len(request.args) < 1:
        level = funcs.get_level_by_code(session['level'])
        return render_template('settings.html', level=level)
    else:
        level = request.args.get('level')
        level_code = funcs.get_level_by_name(level)
        session['level'] = level_code

        level = str(level).capitalize()

        return render_template('settings.html', level=level, msg="Difficult Set to " + level)


# SQL Injection
@app.route('/sql-injection', methods=['POST', 'GET'])
@is_logged
def sql_injection_index():
    if len(request.form) < 1:
        return render_template('vulnerabilities/sql-injection.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        sqli = SQLi

        if session['level'] == 0:
            result = sqli.sqli_low(username=username, password=password)

            return render_template('vulnerabilities/sql-injection.html', msg=result)


# Blind SQL Injection
@app.route('/blind-sql-injection', methods=['POST', 'GET'])
@is_logged
def blind_sql_injection_index():
    if len(request.form) < 1:
        return render_template('vulnerabilities/blind-sql-injection.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        sqli = SQLi

        if session['level'] == 0:
            result = sqli.blind_sqli_low(username=username, password=password)
            return render_template('vulnerabilities/blind-sql-injection.html', msg=result)


# NoSQL Injection
@app.route('/no-sql-injection', methods=['POST', 'GET'])
@is_logged
def no_sql_injection():
    data = None
    if len(request.form) < 1:
        data = mongo_dbm.get_data_all()
        return render_template('vulnerabilities/no-sql-injection.html', data=data)
    else:
        query = request.form.get('car')
        nosqli = NoSQL

        if session['level'] == 0:
            data = nosqli.no_sql_injection_low(query)

        return render_template('vulnerabilities/no-sql-injection.html', data=data)


# Command Injection
@app.route('/cmd-injection', methods=['POST', 'GET'])
@is_logged
def cmd_injection():
    output = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/command_injection.html')
    else:
        query = request.form.get('input')
        ci = CommandInjection
        if session['level'] == 0:
            output = ci.cmd_injection_low(query=query)

        return render_template('vulnerabilities/command_injection.html', msg=output)


# Business Logic Flaw
@app.route('/business-logic')
@is_logged
def business_logic():
    result = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/business-logic.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        bl = BusinessLogic

        if session['level'] == 0:
            result = bl.business_logic_low(username=username, password=password)

        return render_template('vulnerabilities/business-logic.html', msg=result)


# Sensitive Data Exposure
# Index Page
@app.route('/sensitive-data-exposure')
@is_logged
def sensitive_data_exposure():
    if len(request.form) or len(request.args) < 1:
        if session['level'] == 0:
            return render_template('vulnerabilities/sensitive-data-exposure-low.html')
        if session['level'] == 1:
            return render_template('vulnerabilities/sensitive-data-exposure-medium.html')
    else:
        if session['level'] == 0:
            username = request.form.get('username')
            password = request.form.get('password')
            result = "Incorrect Username or Password"
            if username == "adM1n1sTrat0R" and password == "123P4ssW0rd@@":
                result = "Logged in successfully as an Admin"

            return render_template('vulnerabilities/sensitive-data-exposure-low.html', msg=result)
        elif session['level'] == 1:
            return redirect(url_for('sensitive_data_exposure_low_user'))


# Route for medium Vulnerability - User
@app.route('/sensitive-data-exposure/user')
@is_logged
def sensitive_data_exposure_low_user():
    if len(request.args) < 1:
        return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg="Invalid ID")

    user_id = request.args.get('userid')

    if int(user_id) == 1:
        user_id = 2

    data = dbm.get_user_data(userid=user_id)

    return render_template('vulnerabilities/sensitive-data-exposure-medium.html', data=data)


# Route for medium Vulnerability - Admin
@app.route('/sensitive-data-exposure/admin/')
@is_logged
def sensitive_data_exposure_low_admin():
    if len(request.args) < 1:
        return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg="Invalid ID")

    user_id = request.args.get('userid')

    if int(user_id) != 1:
        return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg="Invalid Admin ID")

    data = dbm.get_user_data(userid=user_id)

    return render_template('vulnerabilities/sensitive-data-exposure-medium.html', data=data)


# Route for medium Vulnerability - Admin
@app.route('/sensitive-data-exposure/admin/config')
@is_logged
def sensitive_data_exposure_low_admin_config():
    if len(request.args) < 1:
        return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg="Invalid ID")

    user_id = request.args.get('userid')

    if int(user_id) != 1:
        return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg="Invalid Admin ID")

    msg = "Here are the credentials for dev\n dev-user : BSYpUzIU0yDvvJ3"

    return render_template('vulnerabilities/sensitive-data-exposure-medium.html', msg=msg)


# XML External Entities
@app.route('/xxe', methods=['POST', 'GET'])
@is_logged
def xxe_index():
    result = None
    if len(request.data) < 1:
        return render_template('vulnerabilities/xml-external-entities.html')
    else:
        data = request.data
        xxe = XXE

        if session['level'] == 0:
            result = xxe.xxe_low(data=data)

        return result, {'Content-Type': 'application/xml; charset=UTF-8'}


# Reflected XSS
@app.route('/reflected-xss', methods=['POST', 'GET'])
@is_logged
def reflected_xss():
    msg = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/reflected-xss.html')
    else:
        entry = request.form.get('input')

        if session['level'] == 0:
            msg = "Hi, " + entry

        return render_template('vulnerabilities/reflected-xss.html', msg=msg)


# Stored XSS
@app.route('/stored-xss', methods=['POST', 'GET'])
@is_logged
def stored_xss():
    msg = None
    data = None
    if len(request.form) < 1:
        data = dbm.get_comments()

        return render_template('vulnerabilities/stored-xss.html', data=data)
    else:
        comment = request.form.get('input')
        xss = XSS

        if session['level'] == 0:
            msg, data = xss.stored_xss_low(comment=comment)

        return render_template('vulnerabilities/stored-xss.html', data=data, msg=msg)


# DOM Based XSS
@app.route('/dom-xss', methods=['POST', 'GET'])
@is_logged
def dom_xss():
    msg = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/dom-xss.html')
    else:
        entry = request.form.get('input')

        if session['level'] == 0:
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


# Insecure File Upload
@app.route('/insecure-file-upload', methods=['POST', 'GET'])
@is_logged
def insecure_file_upload():
    result = None
    if len(request.files) < 1:
        return render_template('vulnerabilities/insecure-file-upload.html')
    else:
        uploaded_file = request.files['file']

        if session['level'] == 0:
            if uploaded_file == '':
                result = "No file selected!"
                return render_template('vulnerabilities/insecure-file-upload.html', msg=result)

            full_filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(full_filename)
            result = "File uploaded successfully!"
        elif session['level'] == 1:
            ext = uploaded_file.filename.split('.')[1]

            if uploaded_file.filename == '':
                result = "No file selected!"
                return render_template('vulnerabilities/insecure-file-upload.html', msg=result)
            elif ext != 'img' and ext != 'jpg' and ext != 'jpeg':
                result = "File format not supported!"
            else:
                full_filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
                uploaded_file.save(full_filename)
                result = "File uploaded successfully!"

        return render_template('vulnerabilities/insecure-file-upload.html', msg=result)


# Brute Force
@app.route('/brute-force', methods=['POST', 'GET'])
@is_logged
def brute_force():
    result = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/brute-force.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        bf = BruteForce

        if session['level'] == 0:
            result = bf.brute_force_low(username=username, password=password)

        return render_template('vulnerabilities/brute-force.html', msg=result)


# Directory traversal
@app.route('/directory-traversal', methods=['POST', 'GET'])
@is_logged
def directory_traversal():
    if not request.args:
        return render_template('vulnerabilities/directory-traversal.html')
    else:
        image_name = request.args.get('image')
        if image_name == "NoneType":
            return render_template("vulnerabilities/directory-traversal.html")
        elif image_name in ["cat", "dog", "monkey"]:
            image_name = image_name + ".jpg"
            path = os.path.join("/static/images", image_name)
            return render_template("vulnerabilities/directory-traversal.html", user_image=path)
        else:
            try:
                f = open(image_name, "r")
                result = f.read()
                return render_template("vulnerabilities/directory-traversal.html", msg=result)
            except FileNotFoundError:
                return render_template("vulnerabilities/directory-traversal.html", msg="File not Found")


# HTML Injection
@app.route('/html-injection', methods=['POST', 'GET'])
@is_logged
def html_injection():
    msg = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/html_injection.html')
    else:
        entry = request.form.get('input')

        if session['level'] == 0:
            msg = "Hi, " + entry + ". How are you???"

        return render_template('vulnerabilities/html_injection.html', msg=msg)



# Execute Main
if __name__ == '__main__':
    app.run(debug=True)
