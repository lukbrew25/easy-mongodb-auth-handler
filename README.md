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
├── .github/
│   └── workflows/
│       ├── linter.yml
│       ├── minlinter.yml
│       └── python-package.yml
|── dist/
|   ├── easy_mongodb_auth_handler-1.0.11-py3-none-any.whl
|   └── easy_mongodb_auth_handler-1.0.11.tar.gz
├── src/
│   ├── .gitignore
│   └── easy_mongodb_auth_handler/
│       ├── .gitignore
│       ├── __init__.py
│       ├── auth.py
│       ├── utils.py
│       └── package_functions/
│           ├── __init__.py
│           ├── func.py
│           └── message.py
|── README.md
|── LICENSE
|── requirements.txt
|── minrequirements.txt
|── MANIFEST.in
|── setup.py
|── .gitignore
|── .pylintrc
|── .flake8
└──CONTRIBUTING.md
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
- Multi-factor authentication (MFA) support
- Rate limiting to prevent abuse
- Utility functions for user status management and data retrieval
- Detailed error handling with readable messages or numeric codes
- Support for custom user data storage in a flexible format

## Usage

```
from easy_mongodb_auth_handler import Auth, Utils

auth = Auth(
    mongo_uri="mongodb://localhost:27017", # MongoDB URI for your database (Must match the Utils module's mongo_uri if using both modules)
    db_name="auth", # Database name for user data (Must match the Utils module's db_name if using both modules)
    mail_info={
        "server": "smtp.example.com",
        "port": 587,
        "username": "your_email@example.com",
        "password": "your_email_password"
    }, # Optional: Include if using email verification
    blocking=True/False,  # Optional: True to enable user blocking
    rate_limiting=0 # Optional: Set to 0 to disable rate limiting, or a positive integer to enable rate limiting with that cooldown period in seconds between user requests.
    readable_errors=True/False,  # Optional: False to switch to numeric error codes translated in the README.md file
    attempts=6,  # Optional: Number of attempts for initial MongoDB connection (default is 6).
    delay=10,  # Optional: Delay in seconds between MongoDB initial connection attempts (default is 10 seconds).
    timeout=5000,  # Optional: Timeout in ms for MongoDB connection (default is 5000 ms).
    certs=certifi.where()  # Optional: Path to CA bundle for SSL verification (default is certifi's CA bundle)
)

utils = Utils(
    mongo_uri="mongodb://localhost:27017", # Must match the Auth module's mongo_uri
    db_name="auth", # Must match the Auth module's db_name
    attempts=6,  # Optional: Number of attempts for initial MongoDB connection (default is 6).
    readable_errors=True/False,  # Optional: False to switch to numeric error codes translated in the README.md file
    delay=10,  # Optional: Delay in seconds between MongoDB initial connection attempts (default is 10 seconds).
    timeout=5000,  # Optional: Timeout in ms for MongoDB connection (default is 5000 ms).
    certs=certifi.where()  # Optional: Path to CA bundle for SSL verification (default is certifi's CA bundle)
)
```
This code initializes the modules. The Auth module is used for most functions. The Utils module is used for utility functions that are designed for user management, data retrieval, and status checks that are not intended to directly process user input.
The mail arguments are not required but needed to use verification code functionality. 
Each module can be initialized separately if you only need specific functionalities of one module. Make sure to use the same mongo uri and db name for both modules.
The `blocking` argument is optional and defaults to `True`. If set to `True`, it enables user blocking functionality.
The `rate_limiting` argument is optional and defaults to `0`, which disables rate limiting. If configured with x number of seconds, it will refuse more than two requests per email address in that time period (timer reset upon successful or unsuccessful request).
Both blocking and rate limiting are optional and only affect functions in the Auth module.
The data can be easily accessed externally by connecting to the same mongodb instance, navigating to the database passed to the `db_name` argument, and then accessing the `users`, `blocked`, and `limit` collections.
All methods return True or False (unless the method is meant to return data) with additional detailed outcome reports (as in the following format):
{
    "success": True/False, 
    "message": "specific message or error code"
}

## Function Reference - auth.example_func(args)

All functions return a dictionary: `{"success": True/False, "message": "specific message"}`.

### User Registration & Verification

- **auth.register_user(email, password, custom_data=None)**
  - Registers a user and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.

- **auth.register_user_no_verif(email, password, custom_data=None)**
  - Registers a user without email verification.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.

- **auth.register_user_no_pass(email, custom_data=None)**
  - Registers a user without a password and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.

- **auth.verify_user(email, code)**
  - Verifies a user by checking the provided verification code.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `code` (`str`): Verification code sent to the user.

### Authentication

- **auth.authenticate_user(email, password)**
  - Authenticates a user. Requires the user to be verified.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `mfa` (`bool`, optional): If set to `True`, it will send the user a six-digit code to their email for multi-factor authentication. Defaults to `False`.
- 
- **auth.verify_mfa_code(email, code)**
  - Verifies the multi-factor authentication code sent to the user's email. Can be used in conjunction with register_user_no_pass(), verify_user(), and generate_code() for passwordless sign-in.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `code` (`str`): Six-digit code sent to the user's email.

### MFA Code Management
- **auth.generate_code(email)**
  - Generates and emails a code to the user. Call before password and email resets or when signing in without password.
  - **Parameters:**
    - `email` (`str`): User's email address.

### Password Management

- **auth.reset_password_no_verif(email, old_password, new_password)**
  - Resets the user's password after verifying the old password. No email code required.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `old_password` (`str`): User's current password.
    - `new_password` (`str`): New password to set.

- **auth.verify_reset_code_and_reset_password(email, reset_code, new_password)**
  - Verifies a password reset code and resets the user's password.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `reset_code` (`str`): Code sent to the user's email.
    - `new_password` (`str`): New password to set.

### Email Management

- **auth.change_email_no_verif(email, new_email, password)**
  - Changes the user's email address without requiring email verification.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`): User's password.

- **auth.verify_reset_code_and_change_email(email, reset_code, new_email, password=None)**
  - Changes the user's email address after verifying a reset code sent to their email. Optionally uses password verification if the user has a saved password.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `reset_code` (`str`): Reset code sent to the user's email.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`, optional): User's password for additional verification.

### User Deletion & Blocking
When a user is blocked, they cannot log in or perform any actions that require authentication.

- **auth.delete_user(email, password, del_from_blocking=True)**
  - Deletes a user from the database if credentials match. If `del_from_blocking` is `True`, also removes from the blocking database.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `del_from_blocking` (`bool`, optional): Also remove from blocking database (default: True).

- **auth.delete_user_with_verif(email, password, code, del_from_blocking=True)**
  - Deletes a user from the database if credentials and code match. If `del_from_blocking` is `True`, also removes from the blocking database.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `code` (`str`): Verification code sent to the user's email.
    - `del_from_blocking` (`bool`, optional): Also remove from blocking database (default: True).

- **utils.block_user(email)**
  - Blocks a user by setting their status to "blocked".
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.unblock_user(email)**
  - Unblocks a user.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.is_blocked(email)**
  - Checks if a user is blocked.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.is_verified(email)**
  - Checks if a user is verified.
  - **Parameters:**
    - `email` (`str`): User's email address.

### Custom User Data
Custom user data is a flexible field that can store any type of data. It is stored alongside the normal user data.
Store all custom data in a dictionary format for more storage and to use the 2nd and 4th functions in the section below.
If the method is meant to return data, it will do so in the following format:

{
    "success": True/False,
    "message": "Custom user data if success OR error code if failure"
}

- **utils.get_cust_usr_data(email)**
  - Returns all custom user data for the user.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.get_some_cust_usr_data(email, field)**
  - Returns a specific dictionary entry from the user's custom data. REQUIRES the custom data to be stored in a dictionary format.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `field` (`str`): Dictionary name to retrieve.

- **utils.replace_usr_data(email, custom_data)**
  - Replaces the user's custom data with new data.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `custom_data` (`any`): New custom data to store.

- **utils.update_usr_data(email, field, custom_data)**
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

| Numeric Code | User-Friendly Message                       |
|--------------|---------------------------------------------|
| 200          | Success                                     |
| 201          | Verification email sent.                    |
| 202          | Authentication successful.                  |
| 203          | Password reset successful.                  |
| 204          | User deleted.                               |
| 205          | Custom user data field updated.             |
| 206          | Custom user data changed.                   |
| 207          | User unblocked.                             |
| 300          | User verified.                              |
| 301          | User is not blocked.                        |
| 302          | User is not verified.                       |
| 400          | Error                                       |
| 401          | User exceeded rate limits.                  |
| 402          | User already exists.                        |
| 403          | User is blocked.                            |
| 404          | User not found.                             |
| 410          | Failed to delete user.                      |
| 412          | Field not found.                            |
| 417          | Invalid code.                               |
| 419          | Failed to delete user.                      |
| 420          | User deleted but not from blocked database. |
| 421          | Failed to delete user from all databases.   |
| 423          | User is not found in blocked database.      |
| 500          | Invalid old password.                       |
| 501          | Invalid password.                           |
| 502          | Invalid credentials.                        |
| 503          | Invalid email format.                       |

## License

GNU Affero General Public License v3

## Author

Lukbrew25

...and all future contributors!
