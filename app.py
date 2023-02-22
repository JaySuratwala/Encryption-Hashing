import os
from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import sqlite3
from flask import send_from_directory
from flask import render_template


app = Flask(__name__)

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')
    
# Define the secret key and initialization vector for encryption
SECRET_KEY = b'secret_key'
IV = get_random_bytes(16)

# Define the database connection and cursor 
conn = sqlite3.connect('user_credentials.db')
cursor = conn.cursor()

# Create the user_credentials table if it does not already exist
cursor.execute('''CREATE TABLE IF NOT EXISTS user_credentials (
                id INTEGER PRIMARY KEY,
                email TEXT,
                name TEXT,
                phone_number TEXT,
                password TEXT)''')
conn.commit()


@app.route('/register', methods=['POST','GET'])
def register():
    # Check if email is present in the form data
    if 'email' not in request.form:
        return 'Email address is required'
    
    # Get user data from the request
    email = request.form['email']
    name = request.form['name']
    phone_number = request.form['phone_number']
    password = request.form['password']

    # Encrypt the password using AES
    cipher = AES.new(SECRET_KEY, AES.MODE_CFB, IV)
    encrypted_password = cipher.encrypt(password.encode())

    # Hash the encrypted password using SHA256
    hash_obj = SHA256.new()
    hash_obj.update(encrypted_password)
    hashed_password = hash_obj.digest()

    # Insert the user data into the database
    cursor.execute("INSERT INTO user_credentials (email, name, phone_number, password) VALUES (?, ?, ?, ?)",
                (email, name, phone_number, hashed_password))
    conn.commit()

    return 'User registered successfully!'


@app.route('/login', methods=['POST'])
def login():
    # Get user data from the request
    email = request.form['email']
    password = request.form['password']

    # Retrieve the hashed password from the database
    cursor.execute("SELECT password FROM user_credentials WHERE email=?", (email,))
    hashed_password = cursor.fetchone()[0]

    # Encrypt the password using AES
    cipher = AES.new(SECRET_KEY, AES.MODE_CFB, IV)
    encrypted_password = cipher.encrypt(password.encode())

    # Hash the encrypted password using SHA256
    hash_obj = SHA256.new()
    hash_obj.update(encrypted_password)
    hashed_input_password = hash_obj.digest()

    # Compare the hashed passwords to authenticate the user
    if hashed_input_password == hashed_password:
        return 'User authenticated successfully!'
    else:
        return 'Invalid email or password'


if __name__ == '__main__':
    app.run(debug=True)