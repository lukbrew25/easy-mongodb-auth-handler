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


#pylint: disable=inconsistent-return-statements
#pylint: disable=trailing-whitespace
#pylint: disable=too-many-return-statements


class Auth:
    """
    Handles user authentication and management using MongoDB.
    """

    def __init__(self, mongo_uri, db_name, mail_info=None, blocking=True):
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
        self.mail_info = mail_info or {}
        self.blocking = blocking

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

    def register_user_no_verif(self, email, password, custom_data=False):
        """
        registers a user without email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.

        Returns:
            dict: Success status and message.
        """
        try:
            if not validate_email(email):
                return {"success": False, "message": "Invalid email format."}
            if self._find_user(email):
                return {"success": False, "message": "User already exists."}
            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": "User is blocked."}
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
            return {"success": True, "message": "User registered without verification."}
        except Exception as error:  # pylint: disable=broad-except
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
                return {"success": False, "message": "User not found."}
            if not check_password(user, old_password):
                return {"success": False, "message": "Invalid old password."}
            hashed_password = hash_password(new_password)
            self.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
            return {"success": True, "message": "Password reset successful."}
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "message": str(error)}

    def register_user(self, email, password, custom_data=False):
        """
        registers a user with email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.

        Returns:
            dict: Success status and message.
        """
        try:
            if not validate_email(email):
                return {"success": False, "message": "Invalid email format."}
            if self.users.find_one({"email": email}):
                return {"success": False, "message": "User already exists."}

            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": "User is blocked."}
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
            return {"success": True, "message": "User registered. Verification email sent."}
        except Exception as error:  # pylint: disable=broad-except
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
            blocked_user = self._find_blocked_user(email)
            if not user:
                return {"success": False, "message": "User not found."}
            if self.blocking:
                if not blocked_user:
                    return {"success": False, "message": "User is not found in blocked database."}
                if blocked_user["blocked"]:
                    return {"success": False, "message": "User is blocked."}
            if user["verification_code"] == code:
                self.users.update_one({"email": email}, {"$set": {"verified": True}})
                return {"success": True, "message": "User verified."}
            return {"success": False, "message": "Invalid verification code."}
        except Exception as error:  # pylint: disable=broad-except
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
            blocked_user = self._find_blocked_user(email)
            if not user:
                return {"success": False, "message": "User not found."}
            if self.blocking:
                if not blocked_user:
                    return {"success": False, "message": "User is not found in blocked database."}
                if blocked_user["blocked"]:
                    return {"success": False, "message": "User is blocked."}
            if not user["verified"]:
                return {"success": False, "message": "User not verified."}
            if check_password(user, password):
                return {"success": True, "message": "Authentication successful."}
            return {"success": False, "message": "Invalid credentials."}
        except Exception as error:  # pylint: disable=broad-except
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
                return {"success": False, "message": "User not found."}
            if not check_password(user, password):
                return {"success": False, "message": "Invalid password."}
            result = self.users.delete_one({"email": email})
            if blocked_user:
                if del_from_blocking:
                    block_result = self.blocked.delete_one({"email": email})
                    if block_result.deleted_count == 0:
                        if result.deleted_count == 0:
                            return {"success": False, "message":
                                "Failed to delete user "
                                "from all databases."}
                        return {"success": False, "message": "User deleted but "
                                                             "not from blocked database."}
                elif not blocked_user["blocked"]:
                    self.blocked.delete_one({"email": email})
            if result.deleted_count > 0:
                return {"success": True, "message": "User deleted."}
            return {"success": False, "message": "Failed to delete user."}
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "message": str(error)}

    def generate_reset_code(self, email):
        """
        Generates a password reset code and sends it to the user's email.

        Args:
            email (str): User's email address.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": "User not found."}

            reset_code = generate_secure_code()
            self.users.update_one({"email": email}, {"$set": {"reset_code": reset_code}})
            send_verification_email(self.mail_info, email, reset_code)
            return {"success": True, "message": "Reset code sent to email."}
        except Exception as error:  # pylint: disable=broad-except
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
                return {"success": False, "message": "User not found."}
            if user.get("reset_code") != reset_code:
                return {"success": False, "message": "Invalid reset code."}

            hashed_password = hash_password(new_password)
            self.users.update_one(
                {"email": email}, {"$set": {"password": hashed_password, "reset_code": None}}
            )
            return {"success": True, "message": "Password reset successful."}
        except Exception as error:  # pylint: disable=broad-except
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
                return {"success": False, "message": "User not found."}
            self.blocked.update_one({"email": email}, {"$set": {"blocked": True}})
            return {"success": True, "message": "User blocked."}
        except Exception as error:  # pylint: disable=broad-except
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
                return {"success": False, "message": "User not found."}
            self.blocked.update_one({"email": email}, {"$set": {"blocked": False}})
            return {"success": True, "message": "User unblocked."}
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "message": str(error)}

    def get_cust_usr_data(self, email):
        """
        retrieves custom user data
        Args:
            email (str): User's email address.
        Returns:
            dict: Success status and message.
        """

        user = self.users.find_one({"email": email})

        if not user:
            return {"success": False, "message": "User not found."}
        custom_data = user.get("custom_data")
        if custom_data:
            return {"success": True, "message": custom_data}
        return {"success": True, "message": "No data found."}

    def get_some_cust_usr_data(self, email, field):
        """
        retrieves specific custom user data
        Args:
            email (str): User's email address.
            field (str): Specific field to retrieve.
        Returns:
            dict: Success status and message.
        """
        user = self.users.find_one({"email": email})

        if not user:
            return {"success": False, "message": "User not found."}
        custom_data = user.get("custom_data").get(field)
        if custom_data:
            return {"success": True, "message": custom_data}
        return {"success": True, "message": "No data found."}

    def replace_usr_data(self, email, custom_data):
        """
        replaces custom user data
        Args:
            email (str): User's email address.
            custom_data: New custom data to save with the user.
        Returns:
            dict: Success status and message.
        """
        user = self.users.find_one({"email": email})

        if not user:
            return {"success": False, "message": "User not found."}

        self.users.update_one(
            {"email": email}, {"$set": {"custom_data": custom_data}}
        )
        return {"success": True, "message": "Custom user data changed."}

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
        user = self.users.find_one({"email": email})

        if not user:
            return {"success": False, "message": "User not found."}

        if not user.get("custom_data").get(field):
            return {"success": False, "message": "Field not found."}

        self.users.update_one(
            {"email": email}, {"$set": {f"custom_data.{field}": custom_data}}
        )
        return {"success": True, "message": "Custom user data field updated."}
