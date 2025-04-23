import bcrypt
import secrets
import re
from pymongo import MongoClient
from .utils import send_verification_email


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_secure_code(length=6):
    return ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(length))


def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


class Auth:
    def __init__(self, mongo_uri, db_name, mail_server=None, mail_port=None, mail_username=None, mail_password=None):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.users = self.db['users']
        self.mail_server = mail_server
        self.mail_port = mail_port
        self.mail_username = mail_username
        self.mail_password = mail_password

    def register_user_no_verif(self, email, password):
        if not validate_email(email):
            return {"success": False, "message": "Invalid email format."}
        if self.users.find_one({"email": email}):
            return {"success": False, "message": "User already exists."}

        hashed_password = hash_password(password)
        self.users.insert_one({
            "email": email,
            "password": hashed_password,
            "verified": True  # Automatically verified
        })
        return {"success": True, "message": "User registered without verification."}


    def reset_password_no_verif(self, email, old_password, new_password):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        if not verify_password(old_password, user["password"]):
            return {"success": False, "message": "Invalid old password."}
        hashed_password = hash_password(new_password)
        self.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
        return {"success": True, "message": "Password reset successful."}


    def register_user(self, email, password):
        if not validate_email(email):
            return {"success": False, "message": "Invalid email format."}
        if self.users.find_one({"email": email}):
            return {"success": False, "message": "User already exists."}

        hashed_password = hash_password(password)
        verification_code = generate_secure_code()
        self.users.insert_one({
            "email": email,
            "password": hashed_password,
            "verified": False,
            "verification_code": verification_code
        })
        send_verification_email(self.mail_server, self.mail_port, self.mail_username, self.mail_password, email,
                                verification_code)
        return {"success": True, "message": "User registered. Verification email sent."}


    def verify_user(self, email, code):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        if user["verification_code"] == code:
            self.users.update_one({"email": email}, {"$set": {"verified": True}})
            return {"success": True, "message": "User verified."}
        return {"success": False, "message": "Invalid verification code."}


    def authenticate_user(self, email, password):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        if not user["verified"]:
            return {"success": False, "message": "User not verified."}
        if verify_password(password, user["password"]):
            return {"success": True, "message": "Authentication successful."}
        return {"success": False, "message": "Invalid credentials."}


    def delete_user(self, email, password):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        if not verify_password(password, user["password"]):
            return {"success": False, "message": "Invalid password."}
        result = self.users.delete_one({"email": email})
        if result.deleted_count > 0:
            return {"success": True, "message": "User deleted."}
        return {"success": False, "message": "Failed to delete user."}


    def generate_reset_code(self, email):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        reset_code = generate_secure_code()
        self.users.update_one({"email": email}, {"$set": {"reset_code": reset_code}})
        send_verification_email(self.mail_server, self.mail_port, self.mail_username, self.mail_password, email, reset_code)
        return {"success": True, "message": "Reset code sent to email."}


    def verify_reset_code_and_reset_password(self, email, reset_code, new_password):
        user = self.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found."}
        if user.get("reset_code") != reset_code:
            return {"success": False, "message": "Invalid reset code."}
        hashed_password = hash_password(new_password)
        self.users.update_one({"email": email}, {"$set": {"password": hashed_password, "reset_code": None}})
        return {"success": True, "message": "Password reset successful."}
