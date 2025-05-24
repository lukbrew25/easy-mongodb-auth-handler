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
    db_name="mydb",
    mail_info={
        mail_server="smtp.example.com",
        mail_port=587,
        mail_username="your_email@example.com",
        mail_password="your_email_password"
    }, # Optional: Include if using email verification
    blocking=True/False  # Optional: True to enable user blocking
)
```
This code initializes the package. 
The mail arguments are not required, but needed to use verification code functionality. 
The `blocking` argument is optional and defaults to `True`. If set to `True`, it enables user blocking functionality.
All methods return True or False with additional detailed outcome reports.

## Function Reference - auth.example_func(args)

All functions return a dictionary: `{"success": True/False, "message": "specific message"}`.

### User Registration & Verification

- **register_user(email, password, custom_data=False)**
  - Registers a user and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store.

- **register_user_no_verif(email, password, custom_data=False)**
  - Registers a user without email verification.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store.

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
  - Retrieves a specific dictionary entry from the user's custom data.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `field` (`str`): Dictionary name to retrieve.

- **replace_usr_data(email, custom_data)**
  - Replaces the user's custom data with new data.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `custom_data` (`any`): New custom data to store.

- **update_usr_data(email, field, custom_data)**
  - Updates a specific dictionary entry in the user's custom data.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `field` (`str`): Dictionary name to update.
    - `custom_data` (`any`): New value for the field.

## Requirements

- Python >= 3.8
- pymongo >= 4.0.0
- bcrypt >= 4.0.0

## License

GNU Affero General Public License v3

## Author

Lukbrew25

...and all future contributors!
