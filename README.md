# Encryption-Hashing
<p>This is a Python Flask web application that provides user registration and authentication functionality, with user credentials stored in a SQLite database. The application uses the AES and SHA256 cryptographic algorithms for password encryption and hashing, respectively, to ensure the security of user data.
<br><br>The application has three Flask routes:
<br>•	The index route renders the index.html file.
<br>•	The favicon route serves the favicon.ico file.
<br>•	The register/login routes handle user registration and authentication.
<br><br>The register route validates the email and password provided in the registration form, encrypts and hashes the password using the AES and SHA256 algorithms, respectively, and inserts the user data into the database.
<br><br>The login route retrieves the hashed password from the database for the user with the provided email, encrypts and hashes the password provided in the login form, and compares the two hashed passwords to authenticate the user.
<br><br>The code demonstrates the basic implementation of user authentication and security features. It can be extended to add more features, such as user profile management, session management, and role-based access control.
</p>
