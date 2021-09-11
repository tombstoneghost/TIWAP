# Imports
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from functools import wraps
from random import randint
from jinja2 import Environment
from urllib import parse, error
from helper import functioning
from helper.jwt import JWT
from helper.db_manager import DBManager
from helper.mongodb_manager import MongoDBManager
from vulnerabilities import SQLi, CommandInjection, BusinessLogic, XXE, XSS, BruteForce, NoSQL, HTMLInjection

import os
import requests
import base64
import time
import binascii

# Upload Folder Configuration
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads')

# Certificate Configuration
context = ('certificate/server.crt', 'certificate/server.key')

# Initialize Flask
app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = 'l0G1n_53cR37_k3y'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global Classes/Functions
jwt = JWT()
dbm = DBManager()
mongo_dbm = MongoDBManager()
funcs = functioning
Jinja2 = Environment()

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
        print(session['level'])
        return render_template('settings.html', level=level)
    else:
        level = request.args.get('level')
        level_code = funcs.get_level_by_name(level)
        session['level'] = level_code

        level = str(level).capitalize()

        print(session['level'])

        return render_template('settings.html', level=level, msg="Difficult Set to " + level)


# SQL Injection
@app.route('/sql-injection', methods=['POST', 'GET'])
@is_logged
def sql_injection():
    if len(request.form) < 1:
        return render_template('vulnerabilities/sql-injection.html', level=session['level'])
    else:
        sqli = SQLi

        if session['level'] == 0:
            username = request.form.get('username')
            password = request.form.get('password')
            result = sqli.sqli_low(username=username, password=password)

            return render_template('vulnerabilities/sql-injection.html', msg=result, level=0)

        if session['level'] == 1:
            userid = request.form.get('userid')
            result = sqli.sqli_medium(userid=userid)

            return render_template('vulnerabilities/sql-injection.html', msg=result, level=1)

        if session['level'] == 2:
            usernameId = request.form.get('usernameId')
            result = sqli.sqli_hard(usernameid=usernameId)

            return render_template('vulnerabilities/sql-injection.html', msg=result, level=2)


# Blind SQL Injection
@app.route('/blind-sql-injection', methods=['POST', 'GET'])
@is_logged
def blind_sql_injection():
    if len(request.form) < 1:
        return render_template('vulnerabilities/blind-sql-injection.html', level=session['level'])
    else:
        sqli = SQLi

        if session['level'] == 0:
            username = request.form.get('username')
            password = request.form.get('password')

            result = sqli.blind_sqli_low(username=username, password=password)
            return render_template('vulnerabilities/blind-sql-injection.html', msg=result, level=0)

        if session['level'] == 1:
            userid = request.form.get('userid')
            result = sqli.blind_sqli_medium(userid=userid)

            return render_template('vulnerabilities/sql-injection.html', msg=result, level=1)

        if session['level'] == 2:
            usernameId = request.form.get('usernameId')
            result = sqli.blind_sqli_hard(usernameid=usernameId)

            return render_template('vulnerabilities/sql-injection.html', msg=result, level=2)


# NoSQL Injection
@app.route('/no-sql-injection', methods=['POST', 'GET'])
@is_logged
def no_sql_injection():
    if len(request.form) < 1:
        data = mongo_dbm.get_data_all()
        return render_template('vulnerabilities/no-sql-injection.html', data=data, level=session['level'])
    else:
        query = request.form.get('car')
        nosqli = NoSQL

        if session['level'] == 0 or session['level'] == 1:
            data = nosqli.no_sql_injection_low(query)
            return render_template('vulnerabilities/no-sql-injection.html', data=data, level=session['level'])


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
        elif session['level'] == 1:
            output = ci.cmd_injection_medium(query=query)
        elif session['level'] == 2:
            output = ci.cmd_injection_hard(query=query)

        return render_template('vulnerabilities/command_injection.html', msg=output)


# Business Logic Flaw
@app.route('/business-logic', methods=['POST', 'GET', 'HEAD'])
@is_logged
def business_logic():
    if len(request.form) < 1:
        if session['level'] == 0:
            return render_template('vulnerabilities/business-logic.html')
        elif session['level'] == 1:
            return render_template('vulnerabilities/business-logic-medium.html')
        elif session['level'] == 2:
            return render_template('vulnerabilities/business-logic-hard.html')

    else:
        username = request.form.get('username')
        password = request.form.get('password')
        bl = BusinessLogic

        if session['level'] == 0:
            result = bl.business_logic_low(username=username, password=password)
            return render_template('vulnerabilities/business-logic.html', msg=result)

        elif session['level'] == 1:
            if request.method == 'HEAD':
                result = 'You are now an ADMIN'
            else:
                result = 'Failed... Try harder!!!'
            return render_template('vulnerabilities/business-logic-medium.html', msg=result)
        
        elif session['level'] == 2:
            passwordn = request.form.get('passwordn')
            result = bl.business_logic_hard(username=username, passwordn=passwordn)
            return render_template('vulnerabilities/business-logic-hard.html', msg=result)


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
        if session['level'] == 2:
            return render_template('vulnerabilities/sensitive-data-exposure-hard.html')
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

        elif session['level'] == 2:
            return render_template('vulnerabilities/sensitive-data-exposure-hard.html')


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


# Route for Hard Vulnerability
@app.route('/backups/card-db.bk', methods=['GET', 'POST'])
@is_logged
def sensitive_data_exposure_hard():
    if request.method == 'POST' and '/sensitive-data-exposure' in request.headers.get('Referer'):
        return send_from_directory(directory='backups', filename='card-db.bk')
    else:
        return redirect(url_for('sensitive_data_exposure'))


# XML External Entities
@app.route('/xxe', methods=['POST', 'GET'])
@is_logged
def xxe_index():
    result = None
    if len(request.data) < 1:
        return render_template('vulnerabilities/xml-external-entities.html', level=session['level'])
    else:
        data = request.data
        xxe = XXE

        if session['level'] == 0:
            result = xxe.xxe_low(data=data)
        if session['level'] == 1:
            result = xxe.xxe_medium(data=data)
        if session['level'] == 2:
            if request.headers.get('Content-Type') == 'text/xml':
                result = xxe.xxe_medium(data=data)

        return result, {'Content-Type': 'application/xml; charset=UTF-8'}


# Reflected XSS
@app.route('/reflected-xss', methods=['POST', 'GET'])
@is_logged
def reflected_xss():
    msg = None
    if len(request.form) < 1:
        return render_template('vulnerabilities/reflected-xss.html')
    else:
        entry = request.form.get('name')

        if session['level'] == 0:
            msg = "Hi, " + entry
        if session['level'] == 1:
            if "<script>" in entry.lower():
                msg = "Try Harder"
            else:
                msg = "Hi, " + entry
        if session['level'] == 2:
            if "<script>" in entry.lower() or XSS.filter_input(data=entry):
                msg = "Try Harder"
            else:
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
        comment = request.form.get('comment')
        xss = XSS

        if session['level'] == 0:
            msg, data = xss.stored_xss_low(comment=comment)
        if session['level'] == 1:
            msg, data = xss.stored_xss_medium(comment=comment)
        if session['level'] == 2:
            msg, data = xss.stored_xss_hard(comment=comment)

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
        if session['level'] == 1:
            if "<script>" in entry.lower():
                msg = "Try Harder"
            else:
                msg = "Hi, " + entry
        if session['level'] == 2:
            if session['level'] == 2:
                if "<script>" in entry.lower() or XSS.filter_input(data=entry):
                    msg = "Try Harder"
                else:
                    msg = "Hi, " + entry

        return render_template('vulnerabilities/dom-xss.html', msg=msg)


# HTML Injection
@app.route('/html-injection', methods=['POST', 'GET'])
@is_logged
def html_injection():
    if len(request.form) < 1:
        if session['level'] == 0:
            return render_template('vulnerabilities/html-injection.html')
        if session['level'] == 1:
            data = dbm.get_names()
            return render_template('vulnerabilities/stored-html-injection.html', data=data)
    else:
        entry = request.form.get('input')
        html = HTMLInjection

        if session['level'] == 0:
            msg = "Hi, " + entry + ". How are you???"
            return render_template('vulnerabilities/html-injection.html', msg=msg)

        if session['level'] == 1:
            entry = "Hola! " + entry + ". How are you?"
            msg, data = html.stored_html(name=entry)
            return render_template('vulnerabilities/stored-html-injection.html', data=data, msg=msg)


# Improper Certificate Validation
@app.route('/improper-cert-valid')
@is_logged
def improper_certificate_validation():
    return render_template('vulnerabilities/improper-certificate-validation.html')


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
            elif ext != 'img' or ext != 'jpg' or ext != 'jpeg' or ext != 'png':
                result = "File format not supported!"
            else:
                full_filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
                uploaded_file.save(full_filename)
                result = "File uploaded successfully!"

        elif session['level'] == 2:
            binary = uploaded_file.read(3)

            if uploaded_file.filename == '':
                result = "No file selected!"
                return render_template('vulnerabilities/insecure-file-upload.html', msg=result)

            elif (b'ffd8ff' or b'89504e') in binascii.hexlify(binary):
                full_filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
                uploaded_file.save(full_filename)
                result = "File uploaded successfully!"

            else:
                result = "Try Harder!"


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
        if session['level'] == 1:
            time.sleep(2.0)
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
        elif session['level'] == 0:
            if image_name in ["cat", "dog", "monkey"]:
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
        elif session['level'] == 1:
            if image_name in ["cat", "dog", "monkey"]:
                image_name = image_name + ".jpg"
                path = os.path.join("/static/images", image_name)
                return render_template("vulnerabilities/directory-traversal.html", user_image=path)
            elif "../" in image_name:
                image_name = image_name.replace("../", "")
                try:
                    f = open(image_name, "r")
                    result = f.read()
                    return render_template("vulnerabilities/directory-traversal.html", msg=result)
                except FileNotFoundError:
                    return render_template("vulnerabilities/directory-traversal.html", msg="File not Found")
            else:
                try:
                    f = open(image_name, "r")
                    result = f.read()
                    return render_template("vulnerabilities/directory-traversal.html", msg=result)
                except FileNotFoundError:
                    return render_template("vulnerabilities/directory-traversal.html", msg="File not Found")
        elif session['level'] == 2:
            try:
                url = parse.unquote(image_name)

                f = open(url, 'r')
                result = f.read()

            except error:
                result = "Try Harder"

            return render_template('vulnerabilities/directory-traversal.html', msg=result)


# CSRF
@app.route('/csrf', methods=['POST', 'GET'])
@is_logged
def csrf():
    if len(request.form) < 1:
        return render_template('vulnerabilities/csrf.html')
    else:
        account = request.form.get('account')
        amount = request.form.get('amount')
        csrf_token = request.form.get('csrf_token')

        if session['level'] == 0:
            if int(account) == 110026325 and csrf_token == "QrhjoSBoa7AzQvCY9keq":
                return render_template('vulnerabilities/csrf.html', msg=f"You got the $${amount} money!")
            else:
                return render_template('vulnerabilities/csrf.html', msg="Try to get the Money")
        elif session['level'] == 1:
            referer = request.headers.get('Referer')
            host = request.headers.get('Host')

            if int(account) == 110026325 and csrf_token == "QrhjoSBoa7AzQvCY9keq" and \
                    "/csrf" in referer and host in referer:
                return render_template('vulnerabilities/csrf.html', msg=f"You got the $${amount} money!")
            else:
                return render_template('vulnerabilities/csrf.html', msg="Try to get the Money")


# SSRF
@app.route('/ssrf', methods=['POST', 'GET'])
@is_logged
def ssrf():
    if len(request.args) > 0:
        product = request.args.get('product')
        stock = request.args.get('stock')
        return render_template('vulnerabilities/ssrf.html', product=product, stock=stock)

    if len(request.form) < 1:
        return render_template('vulnerabilities/ssrf.html')
    else:
        product = request.form.get('product')

        if session['level'] == 0:
            requests.get('http://127.0.0.1:5000/api/stock/product?product='+product)
        elif session['level'] == 1:
            if "127.0.0.1" in product:
                return render_template('vulnerabilities/ssrf.html', product=product, stock="NULL")
            else:
                requests.get('http://127.0.0.1:5000/api/stock/product?product=' + product)
        elif session['level'] == 2:
            if "0000:0000:0000:0000:0000:ffff:7f00:0001" in product:
                requests.get('http://127.0.0.1:5000/api/stock/product?product=' + product)
            else:
                return render_template('vulnerabilities/ssrf.html', product=product, stock="NULL")

        return redirect(url_for('check_stock', product=product))


# API to check stock
@app.route('/api/stock/product', methods=['GET', 'POST'])
def check_stock():
    if len(request.args) < 1:
        return redirect(url_for('ssrf'))

    else:
        product = request.args.get('product')

        if session['level'] == 1 or session['level'] == 2:
            product = product.split("&")[1]

        try:
            return requests.get(product).content
        except requests.RequestException:
            pass

        if product != 'none':
            stock = randint(10, 50)
        else:
            stock = 'Invalid'

        return redirect(url_for('ssrf', product=product, stock=stock))


# SSTI
@app.route('/ssti', methods=['POST', 'GET'])
@is_logged
def ssti():
    if len(request.form) < 1:
        return render_template('vulnerabilities/ssti.html')
    else:
        msg = ""
        name = request.form.get('name')

        if session['level'] == 0:
            msg = Jinja2.from_string('Hey, ' + str(name) + "!").render()
        elif session['level'] == 1:
            filters = ["config", "self", "_", '"']

            for f in filters:
                if f in name:
                    msg = "Try Harder"
                    return render_template('vulnerabilities/ssti.html', msg=msg)

            msg = Jinja2.from_string('Hey, ' + str(name) + "!").render()
        elif session['level'] == 2:
            name = base64.b64decode(name)

            msg = Jinja2.from_string('Hey, ' + str(name) + "!").render()

        return render_template('vulnerabilities/ssti.html', msg=msg)


'''
# Security Misconfiguration
@app.after_request
def after_request(response):
    response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
    return response
'''


# Execute Main
if __name__ == '__main__':
    app.run(debug=True, ssl_context=context)
