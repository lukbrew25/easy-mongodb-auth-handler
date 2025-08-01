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
|   ├── easy_mongodb_auth_handler-3.0.0-py3-none-any.whl
|   └── easy_mongodb_auth_handler-3.0.0.tar.gz
├── src/
│   ├── .gitignore
│   └── easy_mongodb_auth_handler/
│       ├── .gitignore
│       ├── __init__.py
│       ├── auth.py
│       ├── utils.py
│       ├── core_db.py
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
- Support for both HTML and plain text email templates
- Support for configuration files

## Usage
Each class has the argument for a configuration file, which is optional. 
If you pass any arguments other than the configuration file, the file will be ignored. Then, you must provide all necessary arguments directly to the class constructor.
If you only pass the configuration file, it will be read and used to set the arguments for the class. The configuration file should be in the same format as the examples below.
If you do not pass any arguments, the class will search for a file in the current directory with the matching name:
.emdb_auth for the Auth class, 
.emdb_utils for the Utils class, 
.emdb_coredb for the CoreDB class. 
Format each file as an .env file. Examples later below.

```
from easy_mongodb_auth_handler import Auth, Utils, CoreDB
import easy_mongodb_auth_handler as emdb

auth = Auth(
    conf_file=".emdb_auth",  # See above: Path to a configuration file for the module - skip if directly passing arguments.
    mongo_uri="mongodb://localhost:27017", # See above: MongoDB URI for your database (Must match the other modules' mongo_uri if using other modules)
    db_name="auth", # See above: Database name for user data (Must match the other modules' db_name if using other modules)
    mail_info={
        "server": "smtp.example.com",
        "port": 587,
        "username": "your_email@example.com",
        "password": "your_email_password"
    }, # Optional: Include if using email verification
    mail_subject="Verification Code", # Optional: Custom subject for verification codes
    mail_body="Your verification code is: {verifcode}", # Optional: Custom email body for verification codes. The text "{verifcode}" is replaced with the verification code. Use HTML or plain text in the template. It is recommended to read the template from a file and pass it here.
    blocking=True/False,  # Optional: True to enable user blocking
    rate_limiting=0, # Optional: Set to 0 to disable rate limiting, or a positive integer to enable rate limiting with that cooldown period in seconds between user requests.
    rate_limit_penalty=0,  # Optional: Set to 0 to disable rate limiting penalty, or a positive integer to set the penalty in seconds for rate limiting. If rate limiting is enabled, this is the penalty in seconds added to the cooldown period for violating the cooldown. Requires `rate_limiting` to be set to a positive integer.
    readable_errors=True/False,  # Optional: False to switch to numeric error codes translated in the README.md file
    code_length=6,  # Optional: Length of the numeric verification code (default is 6 characters).
    db_attempts=6,  # Optional: Number of attempts to initially connect to MongoDB (default is 6).
    db_delay=10,  # Optional: Delay in seconds between MongoDB initial connection attempts (default is 10 seconds).
    db_timeout=5000,  # Optional: Timeout in ms for MongoDB connection (default is 5000 ms).
    certs=certifi.where()  # Optional: Path to CA bundle for SSL verification (default is certifi's CA bundle)
)

utils = Utils(
    conf_file=".emdb_utils",  # See above: Path to a configuration file for the module.
    mongo_uri="mongodb://localhost:27017", # See above: Must match the Auth module's mongo_uri
    db_name="auth", # See above: Must match the Auth module's db_name
    db_attempts=6,  # Optional: Number of attempts for initial MongoDB connection (default is 6).
    readable_errors=True/False,  # Optional: False to switch to numeric error codes translated in the README.md file
    db_delay=10,  # Optional: Delay in seconds between MongoDB initial connection attempts (default is 10 seconds).
    db_timeout=5000,  # Optional: Timeout in ms for MongoDB connection (default is 5000 ms).
    certs=certifi.where()  # Optional: Path to CA bundle for SSL verification (default is certifi's CA bundle)
)

coredb = CoreDB(
    conf_file=".emdb_coredb",  # See above: Path to a configuration file for the module.
    mongo_uri="mongodb://localhost:27017", # See above: Must match the Auth module's mongo_uri
    db_name="auth", # See above: Must match the Auth module's db_name
    db_attempts=6,  # Optional: Number of attempts for initial MongoDB connection (default is 6).
    readable_errors=True/False,  # Optional: False to switch to numeric error codes translated in the README.md file
    db_delay=10,  # Optional: Delay in seconds between MongoDB initial connection attempts (default is 10 seconds).
    db_timeout=5000,  # Optional: Timeout in ms for MongoDB connection (default is 5000 ms).
    certs=certifi.where()  # Optional: Path to CA bundle for SSL verification (default is certifi's CA bundle)
)
```
This code initializes the modules. The Auth module is used for most functions. The Utils module is used for utility functions that are designed for user management, data retrieval, and status checks that are not intended to directly process user input. The CoreDB module is used for direct database interactions, such as manually resetting or deleting the db and collections.
Importing the easy_mongodb_auth_handler package directly is entirely optional and only needed if you want to use the extra functions provided, such as `get_messages()`, `generate_secure_code()`, `get_version()`, and `validate_email()`.
The mail arguments are not required but needed to use verification code functionality. 
Each module can be initialized separately if you only need specific functionalities of one or two module(s). Make sure to use the same mongo uri and db name for all modules.
The `blocking` argument is optional and defaults to `True`. If set to `True`, it enables user blocking functionality.
The `rate_limiting` argument is optional and defaults to `0`, which disables rate limiting. If configured with x number of seconds, it will refuse more than two requests per email address in that time period (timer reset upon successful or unsuccessful request). rate_limit_penalty can be used to add a stackable cooldown penalty to the timer per user.
The mail subject and body arguments can be customized using your own templates. Be sure to include the `{verifcode}` placeholder in the body, as it will be replaced with the actual verification code sent to the user.
Both HTML and plain text formats are supported for the email body. It is recommended to read the email body from a file and pass it to the `mail_body` argument.
Both blocking and rate limiting are optional and only affect functions in the Auth module.
The data can be easily accessed externally by connecting to the same mongodb instance, navigating to the database passed to the `db_name` argument, and then accessing the `users`, `blocked`, and `limit` collections.
All methods return True or False (unless the method is meant to return data) with additional detailed outcome reports (as in the following format) EXCEPT for the CoreDB methods, which have no returns or returns of data.:
{
    "success": True/False, 
    "message": "specific message or error code"
}

## Example (Optional) Configuration Files
If you instantiate the classes without passing any arguments, the modules will look for configuration files in the current directory with the names `.emdb_auth`, `.emdb_utils`, and `.emdb_coredb` depending on what class you are using.
If you pass the `conf_file` argument, the module will read the configuration from that path and file instead.
If any arguments besides 'conf_file' are passed, the configuration file will be completely ignored, and the arguments will be used directly.

### .emdb_auth
```
MONGO_URI=mongodb://localhost:27017
DB_NAME=auth
MAIL_INFO={"server": "smtp.example.com", "port": 587, "username": "youremail@example.com", "password": "yourpassword"}
MAIL_SUBJECT="Verification Code"
MAIL_BODY="Your verification code is: {verifcode}"
BLOCKING=True
RATE_LIMITING=0
RATE_LIMIT_PENALTY=0
READABLE_ERRORS=True
CODE_LENGTH=6
DB_ATTEMPTS=6
DB_DELAY=10
DB_TIMEOUT=5000
CERTS=certifi.where()
```

### .emdb_utils
```
MONGO_URI=mongodb://localhost:27017
DB_NAME=auth
DB_ATTEMPTS=6
DB_DELAY=10
DB_TIMEOUT=5000
READABLE_ERRORS=True
CERTS=certifi.where()
```

### .emdb_coredb
```
MONGO_URI=mongodb://localhost:27017
DB_NAME=auth
DB_ATTEMPTS=6
DB_DELAY=10
DB_TIMEOUT=5000
READABLE_ERRORS=True
CERTS=certifi.where()
```

## Function Reference - modulename.example_func(args)

All functions return a dictionary: `{"success": True/False, "message": "specific message"}`.

### User Registration & Verification

- **auth.register_user(email, password, custom_data=None, cust_length=None, ignore_rate_limit=False)**
  - Registers a user and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.
    - `cust_length` (`int`, optional): Length of the verification code. If None, defaults to the module's `code_length` setting.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.register_user_no_verif(email, password, custom_data=None, ignore_rate_limit=False)**
  - Registers a user without email verification.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.register_user_no_pass(email, custom_data=None, cust_length=None, ignore_rate_limit=False)**
  - Registers a user without a password and sends a verification code via email.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `custom_data` (`any`, optional): Additional user info to store. If None, defaults to an empty dictionary.
    - `cust_length` (`int`, optional): Length of the verification code. If None, defaults to the module's `code_length` setting.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.verify_user(email, code, ignore_rate_limit=False)**
  - Verifies a user by checking the provided verification code.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `code` (`str`): Verification code sent to the user.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

### Authentication

- **auth.authenticate_user(email, password, mfa=False, cust_length=None, ignore_rate_limit=False)**
  - Authenticates a user. Requires the user to be verified.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `mfa` (`bool`, optional): If set to `True`, it will send the user a numeric code to their email for multi-factor authentication. Defaults to `False`.
    - `cust_length` (`int`, optional): Length of the verification code for MFA. If None, defaults to the module's `code_length` setting.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.verify_mfa_code(email, code, ignore_rate_limit=False)**
  - Verifies the multi-factor authentication code sent to the user's email. Can be used in conjunction with register_user_no_pass(), verify_user(), and generate_code() for passwordless sign-in.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `code` (`str`): Numeric code sent to the user's email.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

### MFA Code Management
- **auth.generate_code(email, cust_length=None, ignore_rate_limit=False)**
  - Generates and emails a code to the user. Call before password and email resets or when signing in without password.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `cust_length` (`int`, optional): Length of the verification code. If None, defaults to the module's `code_length` setting.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

### Password Management

- **auth.reset_password_no_verif(email, old_password, new_password, ignore_rate_limit=False)**
  - Resets the user's password after verifying the old password. No email code required.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `old_password` (`str`): User's current password.
    - `new_password` (`str`): New password to set.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.verify_reset_code_and_reset_password(email, reset_code, new_password, ignore_rate_limit=False)**
  - Verifies a password reset code and resets the user's password.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `reset_code` (`str`): Code sent to the user's email.
    - `new_password` (`str`): New password to set.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

### Email Management

- **auth.change_email_no_verif(email, new_email, password, ignore_rate_limit=False)**
  - Changes the user's email address without requiring email verification.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`): User's password.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.verify_reset_code_and_change_email(email, reset_code, new_email, password=None, ignore_rate_limit=False)**
  - Changes the user's email address after verifying a reset code sent to their email. Optionally uses password verification if the user has a saved password.
  - **Parameters:**
    - `email` (`str`): User's current email address.
    - `reset_code` (`str`): Reset code sent to the user's email.
    - `new_email` (`str`): New email address to set.
    - `password` (`str`, optional): User's password for additional verification.
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

### User Deletion & Blocking
When a user is blocked, they cannot log in or perform any actions that require authentication.

- **auth.delete_user(email, password, del_from_blocking=True, ignore_rate_limit=False)**
  - Deletes a user from the database if credentials match. If `del_from_blocking` is `True`, also removes from the blocking database.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `del_from_blocking` (`bool`, optional): Also remove from blocking database (default: True).
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **auth.delete_user_with_verif(email, password, code, del_from_blocking=True, ignore_rate_limit=False)**
  - Deletes a user from the database if credentials and code match. If `del_from_blocking` is `True`, also removes from the blocking database.
  - **Parameters:**
    - `email` (`str`): User's email address.
    - `password` (`str`): User's password.
    - `code` (`str`): Verification code sent to the user's email.
    - `del_from_blocking` (`bool`, optional): Also remove from blocking database (default: True).
    - `ignore_rate_limit` (`bool`, optional): If set to `True`, it will skip the rate limit checking and updating for this request. Defaults to `False`.

- **utils.block_user(email)**
  - Blocks a user by setting their status to "blocked".
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.unblock_user(email)**
  - Unblocks a user.
  - **Parameters:**
    - `email` (`str`): User's email address.

### User Status Checks

- **utils.is_blocked(email)**
  - Checks if a user is blocked (returns status in success portion of dict).
  - **Parameters:**
    - `email` (`str`): User's email address.

- **utils.is_verified(email)**
  - Checks if a user is verified (returns status in success portion of dict).
  - **Parameters:**
    - `email` (`str`): User's email address.

### Rate Limiting

- **utils.time_since_request(email)**
  - Returns the time in seconds since the last request for a user or -1 if error/not found. Only returns int.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **auth.is_rate_limited(email)**
  - Checks if a user is currently rate-limited (returns status in success portion of dict).
  - **Parameters:**
    - `email` (`str`): User's email address.

- **auth.update_rate_limit(email)**
  - Updates the rate limit for a user by setting the time of the last request to current time unless user is under cooldown penalty. Does not return rate limit state - only success of operation.
  - **Parameters:**
    - `email` (`str`): User's email address.

- **auth.check_and_update_rate_limit(email)**
  - Checks if a user is rate-limited (returns status in success portion of dict like most other functions) and updates the last request time to now unless the user is under cooldown penalty.
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

### Module class methods

- **auth.__del__(self)**
  - Closes the MongoDB connection when the module instance is deleted.

- **utils.__del__(self)**
  - Closes the MongoDB connection when the module instance is deleted.

- **coredb.__del__(self)**
  - Closes the MongoDB connection when the module instance is deleted.

### Database Management
The CoreDB module provides functions for managing the MongoDB database and its collections. 
It allows you to create, delete, and reset collections as needed.
These functions have no return values, but they will raise exceptions if the operations fail.
The necessary collections and database will be created automatically when any of the modules are initialized, so you do not need to call these functions unless you want to reset, delete, or re-create the collections or database.

IT IS RECOMMENDED TO RUN THESE FUNCTIONS IN A TRY EXCEPT BLOCK TO HANDLE ANY EXCEPTIONS.
BE CAREFUL when using these functions, as they WILL delete data permanently.

- **coredb.remove_users_collection()**
  - Deletes the `users` collection from the database.

- **coredb.remove_blocked_collection()**
  - Deletes the `blocked` collection from the database.

- **coredb.remove_limit_collection()**
  - Deletes the `limit` collection from the database.

- **coredb.remove_all_collections()**
  - Deletes all collections from the database.

- **coredb.create_users_collection()**
  - Creates the `users` collection in the database.
  
- **coredb.create_blocked_collection()**
  - Creates the `blocked` collection in the database.

- **coredb.create_limit_collection()**
  - Creates the `limit` collection in the database.

- **coredb.create_all_collections()**
  - Creates all collections (`users`, `blocked`, `limit`) in the database.

- **coredb.reset_users_collection()**
  - Resets the `users` collection by deleting the collection and re-creating it.

- **coredb.reset_blocked_collection()**
  - Resets the `blocked` collection by deleting the collection and re-creating it.

- **coredb.reset_limit_collection()**
  - Resets the `limit` collection by deleting the collection and re-creating it.

- **coredb.reset_all_collections()**
  - Resets all collections (`users`, `blocked`, `limit`) by deleting and re-creating them.

- **coredb.remove_db()**
  - Deletes the entire database.

- **coredb.create_db()**
  - Creates the database without any collections.

- **coredb.reset_db()**
  - Resets the database by deleting it, re-creating it, and creating all three collections.

### Statistic Functions
It is still recommended to run these functions in a try except block to handle any exceptions.
These functions dump MongoDB statistics and return the results.

- **coredb.user_count()**
  - Returns the number of users in the `users` collection as int.

- **coredb.db_data_size()**
  - Returns the size of the database in bytes as int.

- **coredb.db_storage_size()**
  - Returns the storage size of the database in bytes as int.

- **coredb.db_index_size()**
  - Returns the size of the indexes in the database in bytes as int.

- **coredb.db_raw_stats()**
  - Returns the raw database statistics as a dictionary.

### Extra functions
Requires using this import statement:

```
import easy_mongodb_auth_handler as emdb
```

- **emdb.get_messages(usr_readable)**
  - Returns a dictionary of all messages used in the package, including error codes and user-friendly messages. Handy for using this package's error codes in your project or for translating errors.
  - **Parameters:**
    - `usr_readable` (`bool`): If `True`, uses user-friendly messages. If `False`, uses numeric error codes.
  - **Returns:**
    - `dict`: A dictionary containing all messages and error codes.

- **emdb.generate_secure_code(length)**
  - Generates a secure numeric code of the specified length.
  - **Parameters:**
    - `length` (`int`): Length of the code to generate.
  - **Returns:**
    - `str`: A string containing the generated numeric code.

- **emdb.get_version()**
  - Returns the current version of the package.
  - **Returns:**
    - `str`: The version number of the package.

- **emdb.validate_email(email)**
  - Validates the format of an email address.
  - **Parameters:**
    - `email` (`str`): The email address to validate.
  - **Returns:**
    - `bool`: `True` if the email format is valid, `False` otherwise.

## Requirements

- Python >= 3.9
- bcrypt >= 4.0.0
- certifi >= 2025.6.15
- python_dotenv >= 1.1.1
- pymongo >= 4.0.0

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
