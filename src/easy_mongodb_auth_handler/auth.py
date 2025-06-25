"""
Authentication and user management for the easy_mongodb_auth_handler package.
"""

from pymongo import MongoClient
from .utils import (
    validate_email,
    hash_password,
    generate_secure_code,
    send_verification_email,
    check_password
)
from .message import get_messages

class Auth:
    """
    Handles user authentication and management using MongoDB.
    """

    def __init__(self, mongo_uri, db_name, mail_info=None, blocking=True, readable_errors=True):
        """
        initializes the Auth class

        Args:
            mongo_uri (str): MongoDB connection URI.
            db_name (str): Name of the database.
            mail_info (dict, optional): Email server configuration with keys:
                'server', 'port', 'username', 'password'.
            blocking (bool): Enable user blocking.
        """
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.users = self.db["users"]
        self.blocked = self.db["blocked"]
        self.mail_info = mail_info
        if self.mail_info:
            if not self.mail_info["server"]:
                raise ValueError("Mail server information is incomplete - missing server key.")
            if not self.mail_info["port"]:
                raise ValueError("Mail server information is incomplete - missing port key.")
            if not self.mail_info["username"]:
                raise ValueError("Mail server information is incomplete - missing username key.")
            if not self.mail_info["password"]:
                raise ValueError("Mail server information is incomplete - missing password key.")
        self.blocking = blocking
        self.messages = get_messages(readable_errors)


    def _find_user(self, email):
        """
        Helper to find a user by email.

        Args:
            email (str): User's email address.

        Returns:
            dict: User document if found, None otherwise.
        """
        return self.users.find_one({"email": email})

    def _find_blocked_user(self, email):
        """
        Helper to find a user's entry in the blocked database by email.

        Args:
            email (str): User's email address.

        Returns:
            dict: User document if found, None otherwise.
        """
        return self.blocked.find_one({"email": email})

    def _block_checker(self, email, user):
        """
        helper to check if a user is blocked.

        Args:
            email (str): User's email address.
            user (dict): User document.

        Returns:
            dict: Error message if user is blocked or not found, None otherwise.
        """
        blocked_user = self._find_blocked_user(email)
        if not user:
            return {"success": False, "message": self.messages["user_not_found"]}
        if self.blocking:
            if not blocked_user:
                return {"success": False, "message": self.messages["not_found_blocked"]}
            if blocked_user["blocked"]:
                return {"success": False, "message": self.messages["user_blocked"]}
        return None

    def register_user_no_verif(self, email, password, custom_data=None):
        """
        registers a user without email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.

        Returns:
            dict: Success status and message.
        """
        if custom_data is None:
            custom_data = {}
        try:
            if not validate_email(email):
                return {"success": False, "message": self.messages["invalid_email"]}
            if self._find_user(email):
                return {"success": False, "message": self.messages["user_exists"]}
            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": self.messages["user_blocked"]}
                else:
                    self.blocked.insert_one({"email": email, "blocked": False})
            hashed_password = hash_password(password)
            self.users.insert_one(
                {
                    "email": email,
                    "password": hashed_password,
                    "blocked": False,
                    "verified": True,
                    "custom_data": custom_data
                }
            )
            return {"success": True, "message": self.messages["success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def reset_password_no_verif(self, email, old_password, new_password):
        """
        resets a user's password without email verification

        Args:
            email (str): User's email address.
            old_password (str): User's current password.
            new_password (str): New password.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if not check_password(user, old_password):
                return {"success": False, "message": self.messages["invalid_old_pass"]}
            hashed_password = hash_password(new_password)
            self.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
            return {"success": True, "message": self.messages["password_reset_success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def change_email_no_verif(self, email, new_email, password):
        """
        resets a user's email without previous email verification

        Args:
            email (str): User's email address.
            new_email (str): User's new email.
            password (str): password.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self.users.find_one({"email": new_email}):
                return {"success": False, "message": self.messages["user_exists"]}
            if not check_password(user, password):
                return {"success": False, "message": self.messages["invalid_pass"]}
            self.users.update_one({"email": email}, {"$set": {"email": new_email}})
            return {"success": True, "message": self.messages["success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def register_user(self, email, password, custom_data=None):
        """
        registers a user with email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.

        Returns:
            dict: Success status and message.
        """
        if custom_data is None:
            custom_data = {}
        if not self.mail_info:
            raise ValueError("Mail server information is required for user verification.")
        try:
            if not validate_email(email):
                return {"success": False, "message": self.messages["invalid_email"]}
            if self.users.find_one({"email": email}):
                return {"success": False, "message": self.messages["user_exists"]}

            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": self.messages["user_blocked"]}
                else:
                    self.blocked.insert_one({"email": email, "blocked": False})
            hashed_password = hash_password(password)
            verification_code = generate_secure_code()
            send_verification_email(self.mail_info, email, verification_code)
            self.users.insert_one(
                {
                    "email": email,
                    "password": hashed_password,
                    "verification_code": verification_code,
                    "blocked": False,
                    "verified": False,
                    "custom_data": custom_data,
                }
            )
            return {"success": True, "message": self.messages["verification_code_sent"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_user(self, email, code):
        """
        verifies a user's email using a verification code.

        Args:
            email (str): User's email address.
            code (str): Verification code.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            output = self._block_checker(email, user)
            if output:
                return output
            if user["verification_code"] == code:
                self.users.update_one({"email": email}, {"$set": {"verified": True}})
                return {"success": True, "message": self.messages["user_verified"]}
            return {"success": False, "message": self.messages["invalid_reset"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def authenticate_user(self, email, password):
        """
        authenticates a user

        Args:
            email (str): User's email address.
            password (str): User's password.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            output = self._block_checker(email, user)
            if output:
                return output
            if not user["verified"]:
                return {"success": False, "message": self.messages["not_verified"]}
            if check_password(user, password):
                return {"success": True, "message": self.messages["authentication_success"]}
            return {"success": False, "message": self.messages["invalid_creds"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def delete_user(self, email, password, del_from_blocking=True):
        """
        deletes a user account

        Args:
            email (str): User's email address.
            password (str): User's password.
            del_from_blocking (bool): Delete the user from the blocked database.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if not check_password(user, password):
                return {"success": False, "message": self.messages["invalid_pass"]}
            result = self.users.delete_one({"email": email})
            if blocked_user:
                if del_from_blocking:
                    block_result = self.blocked.delete_one({"email": email})
                    if block_result.deleted_count == 0:
                        if result.deleted_count == 0:
                            return {"success": False, "message": self.messages["not_deleted_all"]}
                        return {"success": False, "message": self.messages["not_deleted_blocked"]}
                elif not blocked_user["blocked"]:
                    self.blocked.delete_one({"email": email})
            if result.deleted_count > 0:
                return {"success": True, "message": self.messages["user_deleted"]}
            return {"success": False, "message": self.messages["user_not_deleted"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def generate_reset_code(self, email):
        """
        Generates a password reset code and sends it to the user's email.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        if not self.mail_info:
            raise ValueError("Mail server information is required for reset codes.")
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}

            reset_code = generate_secure_code()
            self.users.update_one({"email": email}, {"$set": {"reset_code": reset_code}})
            send_verification_email(self.mail_info, email, reset_code)
            return {"success": True, "message": self.messages["verification_code_sent"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_reset_code_and_reset_password(self, email, reset_code, new_password):
        """
        verifies a reset code and resets the user's password

        Args:
            email (str): User's email address.
            reset_code (str): Reset code.
            new_password (str): New password.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if user.get("reset_code") != reset_code:
                return {"success": False, "message": self.messages["invalid_reset"]}

            hashed_password = hash_password(new_password)
            self.users.update_one(
                {"email": email}, {"$set": {"password": hashed_password, "reset_code": None}}
            )
            return {"success": True, "message": self.messages["password_reset_success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_reset_code_and_change_email(self, email, reset_code, new_email, password=None):
        """
        verifies a reset code and changes the user's email

        Args:
            email (str): User's email address.
            reset_code (str): Reset code.
            new_email (str): New email address.
            password (str, optional): User's password for verification if included.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            user_info = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self.users.find_one({"email": new_email}):
                return {"success": False, "message": self.messages["user_exists"]}
            if user.get("reset_code") != reset_code:
                return {"success": False, "message": self.messages["invalid_reset"]}
            if password:
                if not check_password(user_info, password):
                    return {"success": False, "message": self.messages["invalid_pass"]}

            self.users.update_one(
                {"email": email}, {"$set": {"email": new_email, "reset_code": None}}
            )
            return {"success": True, "message": self.messages["success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def block_user(self, email):
        """
        Blocks a user by changing their entry to blocked.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user or not blocked_user:
                return {"success": False, "message": self.messages["user_not_found"]}
            self.blocked.update_one({"email": email}, {"$set": {"blocked": True}})
            return {"success": True, "message": self.messages["user_blocked"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def unblock_user(self, email):
        """
        Unblocks a user by changing their entry to unblocked.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user or not blocked_user:
                return {"success": False, "message": self.messages["user_not_found"]}
            self.blocked.update_one({"email": email}, {"$set": {"blocked": False}})
            return {"success": True, "message": self.messages["user_unblocked"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def is_blocked(self, email):
        """
        Checks if a user is blocked.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user or not blocked_user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if blocked_user["blocked"]:
                return {"success": True, "message": self.messages["user_blocked"]}
            return {"success": False, "message": self.messages["not_blocked"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def is_verified(self, email):
        """
        Checks if a user is verified.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if user["verified"]:
                return {"success": True, "message": self.messages["user_verified"]}
            return {"success": False, "message": self.messages["not_verified"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def get_cust_usr_data(self, email):
        """
        retrieves custom user data
        Args:
            email (str): User's email address.
        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})

            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            custom_data = user.get("custom_data")
            return {"success": True, "message": custom_data}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def get_some_cust_usr_data(self, email, field):
        """
        retrieves specific custom user data
        Args:
            email (str): User's email address.
            field (str): Specific field to retrieve.
        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            custom_data = user.get("custom_data")
            if custom_data:
                custom_data = user.get("custom_data").get(field)
            return {"success": True, "message": custom_data}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def replace_usr_data(self, email, custom_data):
        """
        replaces custom user data
        Args:
            email (str): User's email address.
            custom_data: New custom data to save with the user.
        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})

            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}

            self.users.update_one(
                {"email": email}, {"$set": {"custom_data": custom_data}}
            )
            return {"success": True, "message": self.messages["data_changed"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def update_usr_data(self, email, field, custom_data):
        """
        updates a specific field in the custom user data
        Args:
            email (str): User's email address.
            field (str): Field to update.
            custom_data: New value for the field.
        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})

            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            temp_check = user.get("custom_data")
            if not temp_check or field not in temp_check:
                return {"success": False, "message": self.messages["field_not_found"]}

            self.users.update_one(
                {"email": email}, {"$set": {f"custom_data.{field}": custom_data}}
            )
            return {"success": True, "message": self.messages["data_changed"]}
        except Exception as error:
            return {"success": False, "message": str(error)}
