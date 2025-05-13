"""
Utility functions for the easy_mongodb_auth_handler package.
"""

import secrets
import re
import smtplib
from email.mime.text import MIMEText
import bcrypt


def check_password(user, password):
    """
    Helper to verify a user's password.

    Args:
        user (dict): User document.
        password (str): Password to verify.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    return verify_password(password, user["password"])


def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(password, hashed):
    """
    verifies a password against a hashed password

    Args:
        password (str): The plain text password.
        hashed (str): The hashed password.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_secure_code(length=6):
    """
    Generates a secure alphanumeric code.

    Args:
        length (int): The length of the code. Default is 6.

    Returns:
        str: The generated code.
    """
    return ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(length))


def validate_email(email):
    """
    Validates the format of an email address using a regular expression.

    Args:
        email (str): The email address to validate.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def send_verification_email(mail_info, recipient_email, verification_code):
    """
    sends a verification email with a specified code to the recipient

    Args:
        mail_info (dict): The server address, port, email address, and password.
        recipient_email (str): The recipient's email address.
        verification_code (str): The verification code to send.

    Raises:
        ValueError: If mail server settings are incomplete.
        RuntimeError: If sending the email fails.
    """
    mail_server = mail_info.get("server")
    mail_port = mail_info.get("port")
    mail_username = mail_info.get("username")
    mail_password = mail_info.get("password")
    if not all([mail_server, mail_port, mail_username, mail_password]):
        raise ValueError("Mail server settings are incomplete or missing.")

    subject = "Your Verification Code"
    body = f"Your verification code is: {verification_code}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = mail_username
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(mail_server, mail_port) as server:
            server.starttls()
            server.login(mail_username, mail_password)
            server.sendmail(mail_username, recipient_email, msg.as_string())
    except Exception as e:
        raise RuntimeError(f"Failed to send email: {e}") from e
