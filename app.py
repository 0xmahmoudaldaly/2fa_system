from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os

app = Flask(__name__)
app.secret_key = 'secret-key'

USERS_FILE = 'users.json'

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

@app.route('/', methods=['GET'])
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=None)

    username = request.form.get('username')
    password = request.form.get('password')
    users = load_users()
	
	if username in users and check_password_hash(users[username]['password'], password):
		session['username'] = username
		return redirect('/2fa')
		
		return render_template('login.html', error='Invalid username or password')

import pyotp
import qrcode

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

@app.route('/2fa', methods=['GET'])
def two_fa():
    username = session.get('username')
    if not username:
        return redirect('/login')

    users = load_users()
    user = users.get(username)

    if not user['totp_secret']:
        secret = pyotp.random_base32()
        user['totp_secret'] = secret
        save_users(users)

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name="SecureApp")
        img = qrcode.make(uri)
        img.save('static/qrcode.png')

        return render_template('verify_2fa.html', show_qr=True)

    return render_template('verify_2fa.html', show_qr=False)

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    username = session.get('username')
    if not username:
        return redirect('/login')

    token = request.form.get('token')
    users = load_users()
    secret = users[username]['totp_secret']
    totp = pyotp.TOTP(secret)

    if totp.verify(token):
        return render_template("success.html")

    return render_template("verify_2fa.html", show_qr=False, error="Invalid 2FA code.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', error=None)

    username = request.form.get('username')
    password = request.form.get('password')
    users = load_users()

    if username in users:
        return render_template('register.html', error="Username already exists.")

   	 hashed_password = generate_password_hash(password)
	users[username] = {
 	   "password": hashed_password,
  	  "totp_secret": None
	}

    save_users(users)
    return render_template('register.html', success="Account created successfully. You can now log in.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

