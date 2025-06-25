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
|-─ dist/[builds here]
├── src/
│   └── easy_mongodb_auth_handler/
│       ├── __init__.py
│       ├── auth.py
│       └── utils.py
|── README.md
|── LICENSE
|── requirements.txt
|-- MANIFEST.in
|── setup.py
|── .gitignore
|── .pylintrc
|--CONTRIBUTING.md
```

## Features

- User registration with and without email verification
- Email format validation
- Secure password hashing with bcrypt
- User login/authentication
- Password reset via email verification
- MongoDB-based user data persistence
- Saving custom per user data
- User blocking functionality
- Email change with or without verification

## Usage

```
from easy_mongodb_auth_handler import Auth

auth = Auth(
    mongo_uri="mongodb://localhost:27017",
    db_name="mydb",
    mail_info={
        "server": "smtp.example.com",
        "port": 587,
        "username": "your_email@example.com",
        "password": "your_email_password"
    }, # Optional: Include if using email verification
    blocking=True/False,  # Optional: True to enable user blocking
    readable_errors=True/False  # Optional: False to switch to numeric error codes translated in the README.md file
)
```
This code initializes the package. 
The mail arguments are not required, but needed to use verification code functionality. 
The `blocking` argument is optional and defaults to `True`. If set to `True`, it enables user blocking functionality.
All methods return True or False with additional detailed outcome reports.

## Function Reference - auth.example_func(args)

All functions return a dictionary: `{"success": True/False, "message": "specific message"}`.

### User Registration & Verification

- **register_user(email, password, custom_data=None)**
  - Registers a user and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.

- **register_user_no_verif(email, password, custom_data=None)**
  - Registers a user without email verification.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.

- **verify_user(email, code)**
  - Verifies a user by checking the provided verification code.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `code` (`str`): Verification code sent to the user.

### Authentication

- **authenticate_user(email, password)**
  - Authenticates a user. Requires the user to be verified.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.

### Password Management

- **reset_password_no_verif(email, old_password, new_password)**
  - Resets the user's password after verifying the old password. No email code required.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `old_password` (`str`): User's current password.
    - `new_password` (`str`): New password to set.

- **generate_reset_code(email)**
  - Generates and emails a password reset code to the user.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **verify_reset_code_and_reset_password(email, reset_code, new_password)**
  - Verifies a password reset code and resets the user's password.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `reset_code` (`str`): Code sent to the user's email.
    - `new_password` (`str`): New password to set.

### Email Management

- **change_email_no_verif(email, new_email, password)**
  - Changes the user's email address without requiring email verification.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`): User's password.

- **verify_reset_code_and_change_email(email, reset_code, new_email, password=None)**
  - Changes the user's email address after verifying a reset code sent to their email. Optionally verifies the password.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `reset_code` (`str`): Reset code sent to the user's email.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`, optional): User's password for additional verification.

### User Deletion & Blocking
When a user is blocked, they cannot log in or perform any actions that require authentication.

- **delete_user(email, password, del_from_blocking=True)**
  - Deletes a user from the database if credentials match. If `del_from_blocking` is `True`, also removes from the blocking database.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `del_from_blocking` (`bool`, optional): Also remove from blocking database (default: True).

- **block_user(email)**
  - Blocks a user by setting their status to "blocked".
  - **Parameters:**
    - `email` (`str`): User's email address.

- **unblock_user(email)**
  - Unblocks a user.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **is_blocked(email)**
  - Checks if a user is blocked.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **is_verified(email)**
  - Checks if a user is verified.
  - **Parameters:**
    - `email` (`str`): User's email address.

### Custom User Data
Custom user data is a flexible field that can store any type of data. It is stored alongside the normal user data.
Store all custom data in a dictionary format for more storage and to use the 2nd and 4th functions in the section below.

- **get_cust_usr_data(email)**
  - Retrieves all custom user data for the user.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **get_some_cust_usr_data(email, field)**
  - Retrieves a specific dictionary entry from the user's custom data. REQUIRES the custom data to be stored in a dictionary format.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `field` (`str`): Dictionary name to retrieve.

- **replace_usr_data(email, custom_data)**
  - Replaces the user's custom data with new data.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `custom_data` (`any`): New custom data to store.

- **update_usr_data(email, field, custom_data)**
  - Updates a specific dictionary entry in the user's custom data. REQUIRES the custom data to be stored in a dictionary format.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `field` (`str`): Dictionary name to update.
    - `custom_data` (`any`): New value for the field.

## Requirements

- Python >= 3.8
- pymongo >= 4.0.0
- bcrypt >= 4.0.0

## Return code translation
These codes are returned by the functions in the package if `readable_errors` is set to `False`.
Error codes starting with 2xx indicate success, while those starting with 4xx indicate errors. 
3xx codes indicate user status checks. 5xx codes indicate authentication errors.

| Numeric Code | User-Friendly Message                              |
|--------------|----------------------------------------------------|
| 200          | Success                                            |
| 201          | Verification email sent.                           |
| 202          | Authentication successful.                         |
| 203          | Password reset successful.                         |
| 204          | User deleted.                                      |
| 205          | Custom user data field updated.                    |
| 206          | Custom user data changed.                          |
| 207          | User unblocked.                                    |
| 300          | User verified.                                     |
| 301          | User is not blocked.                               |
| 302          | User is not verified.                              |
| 400          | Error                                              |
| 402          | User already exists.                               |
| 403          | User is blocked.                                   |
| 404          | User not found.                                    |
| 410          | Failed to delete user.                             |
| 412          | Field not found.                                   |
| 417          | Invalid code.                                      |
| 419          | Failed to delete user.                             |
| 420          | User deleted but not from blocked database.        |
| 421          | Failed to delete user from all databases.          |
| 423          | User is not found in blocked database.             |
| 500          | Invalid old password.                              |
| 501          | Invalid password.                                  |
| 502          | Invalid credentials.                               |
| 503          | Invalid email format.                              |

## License

GNU Affero General Public License v3

## Author

Lukbrew25

...and all future contributors!
