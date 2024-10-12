import random
import re
import string
import zipfile
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/choose')
def choose():
    return render_template('choose.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/index1')
def index1():
    return render_template('index1.html')

@app.route('/index3')
def index3():
    return render_template('index3.html')

@app.route('/index2')
def index2():
    return render_template('index2.html')
@app.route('/index4')
def index4():
    return render_template('index4.html')

@app.route('/passwordstr')
def passwordstr():
    return render_template('passwordstr.html')

def check_password_strength(password):
    length_score = min(1, len(password) / 12)  
    complexity_score = min(1, len(set(password)) / 12)  
    uppercase_score = 1 if re.search(r'[A-Z]', password) else 0  
    lowercase_score = 1 if re.search(r'[a-z]', password) else 0  
    digit_score = 1 if re.search(r'[0-9]', password) else 0  
    special_char_score = 1 if re.search(r'[^A-Za-z0-9]', password) else 0  

    common_patterns = ["password", "123456", "qwerty", "abc123", "letmein", "welcome", "football", "admin", "princess"]
    pattern_score = 0
    for pattern in common_patterns:
        if pattern in password.lower():
            pattern_score -= 0.2 
    strength_score = (length_score + complexity_score + uppercase_score +
                      lowercase_score + digit_score + special_char_score + pattern_score) / 7
    characters = 26 + 26 + 10 + 33  
    possible_combinations = characters ** len(password)
    time_to_crack_seconds = possible_combinations / (10 ** 9) 
    return strength_score * 100, time_to_crack_seconds
@app.route('/check_password', methods=['POST'])
def check_password():
    password = request.form['password']
    strength_percentage, time_to_crack_seconds = check_password_strength(password)
    return render_template('passwordstr.html', password=password, strength=strength_percentage)


def generate_strong_password(length=12):
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    special_characters = string.punctuation

    all_characters = uppercase_letters + lowercase_letters + digits + special_characters

    password = random.choice(uppercase_letters) + \
               random.choice(lowercase_letters) + \
               random.choice(digits) + \
               random.choice(special_characters)

    password += ''.join(random.choice(all_characters) for _ in range(length - 4))

    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)

    return password
@app.route('/index9')
def index9():
    strong_password = generate_strong_password()
    return render_template('index9.html', password=strong_password)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    key = load_key()
    if key is None:
        return "Encryption key not found"

    f = Fernet(key)

    file = request.files['file']
    original = file.read()
    encrypted = f.encrypt(original)

    encrypted_filename = 'enc_' + file.filename
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    key_filename = 'secret_key_' + file.filename + '.txt'
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
    with open(key_path, 'w') as key_file:
        key_file.write(key.decode())

    zip_filename = 'encrypted_file.zip'
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        zip_file.write(encrypted_path, os.path.basename(encrypted_path))
        zip_file.write(key_path, os.path.basename(key_path))

    return send_file(zip_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = request.form['key']
    if key is None:
        return "Decryption key not found"

    f = Fernet(key)

    file = request.files['file']
    encrypted = file.read()
    decrypted = f.decrypt(encrypted)

    decrypted_filename = 'dec_' + file.filename
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
    with open(decrypted_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    return send_file(decrypted_path, as_attachment=True)
@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    key = load_key()
    if key is None:
        return "Encryption key not found"

    f = Fernet(key)

    plaintext = request.form['plaintext'].encode()
    encrypted = f.encrypt(plaintext)
    return render_template('encrypt_text.html', key=key.decode(), encrypted=encrypted.decode())

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text():
    key = request.form['key']
    if key is None:
        return "Decryption key not found"

    f = Fernet(key)

    ciphertext = request.form['ciphertext'].encode()
    decrypted = f.decrypt(ciphertext)

    return render_template('decrypt.html',decrypt=decrypted.decode())

@app.route('/encrypt_audio', methods=['POST'])
def encrypt_audio():
    key = load_key()
    if key is None:
        return "Encryption key not found"

    f = Fernet(key)

    audio = request.files['audio']
    original = audio.read()
    encrypted = f.encrypt(original)

    encrypted_filename = 'enc_' + audio.filename
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    key_filename = 'secret_key_' + audio.filename + '.txt'  # Add .txt extension
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

    # Create a zip file containing both the encrypted audio file and the key file
    zip_filename = 'encrypted_audio_files.zip'
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        zip_file.write(encrypted_path, os.path.basename(encrypted_path))
        zip_file.write(key_path, os.path.basename(key_path))

    # Send the zip file as an attachment
    return send_file(zip_path, as_attachment=True)

@app.route('/decrypt_audio', methods=['POST'])
def decrypt_audio():
    key = request.form['key']
    if key is None:
        return "Decryption key not found"

    f = Fernet(key)

    audio = request.files['audio']
    encrypted = audio.read()
    decrypted = f.decrypt(encrypted)

    decrypted_filename = 'dec_' + audio.filename
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
    with open(decrypted_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    return send_file(decrypted_path, as_attachment=True)

@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    key = load_key()
    if key is None:
        return "Encryption key not found"

    f = Fernet(key)

    image = request.files['image']
    original = image.read()
    encrypted = f.encrypt(original)

    encrypted_filename = 'enc_' + image.filename
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    key_filename = 'secret_key_' + image.filename + '.txt'  # Add .txt extension
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

    # Create a zip file containing both the encrypted image file and the key file
    zip_filename = 'encrypted_image_files.zip'
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        zip_file.write(encrypted_path, os.path.basename(encrypted_path))
        zip_file.write(key_path, os.path.basename(key_path))

    # Send the zip file as an attachment
    return send_file(zip_path, as_attachment=True)

@app.route('/decrypt_image', methods=['POST'])
def decrypt_image():
    key = request.form['key']
    if key is None:
        return "Decryption key not found"

    f = Fernet(key)

    image = request.files['image']
    encrypted = image.read()
    decrypted = f.decrypt(encrypted)

    decrypted_filename = 'dec_' + image.filename
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
    with open(decrypted_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    return send_file(decrypted_path, as_attachment=True)

def load_key():
    key_file = 'mykey.key'
    if os.path.exists(key_file):
        if os.path.getsize(key_file) == 0:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        else:
            with open(key_file, 'rb') as f:
                key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

if __name__ == '__main__':
    app.run(debug=True) 