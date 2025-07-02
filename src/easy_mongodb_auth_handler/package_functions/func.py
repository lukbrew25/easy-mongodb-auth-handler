"""
Utility functions for the easy_mongodb_auth_handler package.
"""

import secrets
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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


def generate_secure_code(length):
    """
    Generates a secure alphanumeric code.

    Args:
        length (int): The length of the code.

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


def send_verification_email(mail_info,
                            recipient_email, verification_code,
                            subject=None, body=None):
    """
    sends a verification email with a specified code to the recipient

    Args:
        mail_info (dict): The server address, port, email address, and password.
        recipient_email (str): The recipient's email address.
        verification_code (str): The verification code to send.
        subject (str, optional): Custom email subject. Uses default if None.
        body (str, optional): Custom email body. Uses default if None.

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

    if subject is None:
        subject = "Verification Code"
    if body is None:
        body = "Your verification code is: {verifcode}"

    final_subject = subject.replace("{verifcode}", verification_code)
    final_body = body.replace("{verifcode}", verification_code)

    # Check if body contains HTML tags to determine content type
    is_html = any(tag in final_body.lower() for
                  tag in ['<html>', '<body>', '<p>', '<br>',
                          '<div>', '<span>'])
    if is_html:
        msg = MIMEMultipart('alternative')
        msg["Subject"] = final_subject
        msg["From"] = mail_username
        msg["To"] = recipient_email

        # Create plain text version by removing HTML tags (simple approach)
        plain_text = re.sub(r'<[^>]+>', '', final_body)
        plain_text = re.sub(r'\s+', ' ', plain_text).strip()

        # Create the text and HTML parts
        text_part = MIMEText(plain_text, 'plain')
        html_part = MIMEText(final_body, 'html')

        # Add parts to message
        msg.attach(text_part)
        msg.attach(html_part)
    else:
        # Simple text message
        msg = MIMEText(final_body)
        msg["Subject"] = final_subject
        msg["From"] = mail_username
        msg["To"] = recipient_email

    try:
        with smtplib.SMTP(mail_server, mail_port) as server:
            server.starttls()
            server.login(mail_username, mail_password)
            server.sendmail(mail_username, recipient_email, msg.as_string())
    except Exception as e:
        raise RuntimeError(f"Failed to send email: {e}") from e
