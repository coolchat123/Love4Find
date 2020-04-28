from flask import Flask, redirect, url_for, render_template, request
import sqlite3
import hashlib, binascii, os

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

app = Flask(__name__)


@app.route("/", methods=['GET'])
def home():
    if request.method == 'GET':
        username = request.form.get('un')
        password = request.form.get('pass')
        print(username)
        print(password)
        conn = sqlite3.connect('passmanage.db')
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS user(
                        username text, 
                        password text
                        )""")
        c.execute("INSERT INTO user VALUES (?, ?);", (username, password))
        conn.commit()
        conn.close()

        return render_template("login.html")



if __name__ == "__main__":
    app.run()