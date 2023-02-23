<?php
use Crypto\Cipher\AES;
use Crypto\Hash\SHA256;
use Crypto\Random\get_random_bytes;

require_once "vendor/autoload.php";

use SQLite3;

$app = new \Flask(__name__);

$app->route('/', function () {
    return 'Welcome to my Flask application!';
});

$app->route('/favicon.ico', function () {
    return $app->send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', ['mimetype' => 'image/vnd.microsoft.icon']);
});

// Define the secret key and initialization vector for encryption
define('SECRET_KEY', 'secret_key');
define('IV', get_random_bytes(16));

// Define the database connection and cursor
$conn = new SQLite3('user_credentials.db');

// Create the user_credentials table if it does not already exist
$conn->exec('CREATE TABLE IF NOT EXISTS user_credentials (
                id INTEGER PRIMARY KEY,
                email TEXT,
                name TEXT,
                phone_number TEXT,
                password TEXT)');

$app->route('/register', function () use ($app) {
    // Get user data from the request
    $email = $app->request->form['email'];
    $name = $app->request->form['name'];
    $phone_number = $app->request->form['phone_number'];
    $password = $app->request->form['password'];

    // Encrypt the password using AES
    $cipher = new AES(SECRET_KEY, AES::MODE_CFB, IV);
    $encrypted_password = $cipher->encrypt($password);

    // Hash the encrypted password using SHA256
    $hash_obj = new SHA256();
    $hash_obj->update($encrypted_password);
    $hashed_password = $hash_obj->digest();

    // Insert the user data into the database
    $stmt = $conn->prepare('INSERT INTO user_credentials (email, name, phone_number, password) VALUES (:email, :name, :phone_number, :hashed_password)');
    $stmt->bindValue(':email', $email);
    $stmt->bindValue(':name', $name);
    $stmt->bindValue(':phone_number', $phone_number);
    $stmt->bindValue(':hashed_password', $hashed_password);
    $stmt->execute();

    return 'User registered successfully!';
});

$app->route('/login', function () use ($app) {
    // Get user data from the request
    $email = $app->request->form['email'];
    $password = $app->request->form['password'];

    // Retrieve the hashed password from the database
    $stmt = $conn->prepare('SELECT password FROM user_credentials WHERE email=:email');
    $stmt->bindValue(':email', $email);
    $result = $stmt->execute();
    $hashed_password = $result->fetchArray()[0];

    // Encrypt the password using AES
    $cipher = new AES(SECRET_KEY, AES::MODE_CFB, IV);
    $encrypted_password = $cipher->encrypt($password);

    // Hash the encrypted password using SHA256
    $hash_obj = new SHA256();
    $hash_obj->update($encrypted_password);
    $hashed_input_password = $hash_obj->digest();

    // Compare the hashed passwords to authenticate the user
    if ($hashed_input_password == $hashed_password) {
        return 'User authenticated successfully!';
    } else {
        return 'Invalid email or password';
    }
});

$app->run();