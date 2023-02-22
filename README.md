# Encryption-Hashing
This is a Python Flask web application that provides user registration and authentication functionality, with user credentials stored in a SQLite database. The application uses the AES and SHA256 cryptographic algorithms for password encryption and hashing, respectively, to ensure the security of user data.
The application has three Flask routes:
•	The index route renders the index.html file.
•	The favicon route serves the favicon.ico file.
•	The register/login routes handle user registration and authentication.
The register route validates the email and password provided in the registration form, encrypts and hashes the password using the AES and SHA256 algorithms, respectively, and inserts the user data into the database.
The login route retrieves the hashed password from the database for the user with the provided email, encrypts and hashes the password provided in the login form, and compares the two hashed passwords to authenticate the user.
The code demonstrates the basic implementation of user authentication and security features. It can be extended to add more features, such as user profile management, session management, and role-based access control.
