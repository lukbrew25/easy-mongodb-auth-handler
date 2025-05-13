# easy_mongodb_auth_handler

A user authentication and verification system using MongoDB, supporting email-based verification, password hashing, and reset mechanisms.

## Installation

```
pip install easy-mongodb-auth-handler
```

## Setup

Make sure you have MongoDB installed and running. You also need access to an SMTP mail server for sending verification and reset codes.

## Project Structure

```
easy_mongodb_auth_handler/
├── setup.py
├── src/
│   └── easy_mongodb_auth_handler/
│       ├── __init__.py
│       ├── auth.py
│       └── utils.py
```

## Features

- User registration with and without email verification
- Email format validation
- Secure password hashing with bcrypt
- User login/authentication
- Password reset via email verification
- MongoDB-based user data persistence

## Usage

```
from easy_mongodb_auth_handler import Auth

auth = Auth(
    mongo_uri="mongodb://localhost:27017",
    db_name="myapp",
    mail_server="smtp.example.com",
    mail_port=587,
    mail_username="your_email@example.com",
    mail_password="your_email_password"
)
```
This code initializes the package. The mail arguments are not required, but needed to use verification code functionality. All methods return True or False with additional detailed outcome reports.

### Function Reference - auth.func_name(params)

All following functions return a dictionary with the following values: {"success": True/False Boolean, "message": "specific error or success message string"}.

```
register_user(email, password, blocking=True)
```
Registers a user and sends a verification code via email. Returns a success status and message. Blocking is an optional parameter that is set to True by default. When blocking is set to True, the user will not be allowed to register if they are blocked.

```
verify_user(email, code, blocking=True)
```
Verifies a user by checking the provided verification code against the database entry. Blocking is an optional parameter that is set to True by default. When blocking is set to True, the user will not be allowed to verify if they are blocked.

```
authenticate_user(email, password, blocking=True)
```
Authenticates a user by checking their email and password. Requires the user to be verified. Blocking is an optional parameter that is set to True by default. When blocking is set to True, the user will not be allowed to authenticate if they are blocked.

```
delete_user(email, password, del_from_blocking=True) 
```
Deletes a user from the database if credentials match. del_from_blocking is a boolean that determines if the user should be removed from the blocking database if they are currently blocked. If set to true, the entry will be deleted and the user will no longer be blocked. It is optional but set to True by default.

```
register_user_no_verif(email, password, blocking=True)  
```
Registers a user without requiring email verification. Useful for internal tools or test environments. Blocking is an optional parameter that is set to True by default. When blocking is set to True, the user will not be allowed to register if they are blocked.

```
reset_password_no_verif(email, old_password, new_password)
```
Resets the user's password after verifying the old password. Does not require an email code.

```
generate_reset_code(email)
```
Generates and emails a password reset code to the user.

```
verify_reset_code_and_reset_password(email, reset_code, new_password)  
```
Verifies a password reset code and resets the user's password.

```
block_user(email)
```
Blocks a user by setting their status to "blocked" in the database. This prevents login attempts and most functions.

## Requirements

- Python >= 3.8
- pymongo >= 4.0.0
- bcrypt >= 4.0.0

## License

GNU Affero General Public License v3

## Author

Lukbrew25

...and all future contributors!
