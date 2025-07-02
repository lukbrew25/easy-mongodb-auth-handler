"""
Authentication and user management for the easy_mongodb_auth_handler package.
"""

import time
from pymongo import MongoClient
import certifi
from .package_functions.func import (
    validate_email,
    hash_password,
    generate_secure_code,
    send_verification_email,
    check_password
)
from .package_functions.message import get_messages


class Auth:
    """
    Handles user authentication and management using MongoDB.
    """

    def __init__(self, mongo_uri, db_name, mail_info=None,
                 mail_subject="Verification Code",
                 mail_body="Your verification code is: {verifcode}",
                 blocking=True, rate_limit=0, penalty=0, readable_errors=True,
                 attempts=6, delay=10, timeout=5000,
                 certs=certifi.where()):
        """
        initializes the Auth class

        Args:
            mongo_uri (str): MongoDB connection URI.
            db_name (str): Name of the database.
            mail_info (dict, optional): Email server configuration with keys:
                'server', 'port', 'username', 'password'.
            mail_subject (str, optional): Custom email subject template.
                Use {verifcode} placeholder for verification code.
                Defaults to "Verification Code".
            mail_body (str, optional): Custom email body template.
                Use {verifcode} placeholder for verification code.
                Supports both plain text and HTML.
                Defaults to "Your verification code is: {verifcode}".
            blocking (bool): Enable user blocking.
            rate_limit (int): Rate limit for user actions in seconds.
            penalty (int): Penalty time in seconds for rate limiting.
            readable_errors (bool): Use readable error messages.
            attempts (int): Number of connection attempts.
            delay (int): Delay between connection attempts in seconds.
            timeout (int): Timeout in milliseconds for MongoDB connection.
            certs (str): Path to CA bundle for SSL verification.
        """
        self.db = None
        self.retry_count = 0
        if attempts < 1:
            raise ValueError("Number of attempts must be at least 1.")
        if delay < 0:
            raise ValueError("Delay must be a non-negative integer.")
        self.max_retries = attempts
        while self.db is None and self.retry_count < self.max_retries:
            try:
                self.client = MongoClient(mongo_uri,
                                          serverSelectionTimeoutMS=timeout,
                                          tlsCAFile=certs
                                          )
                self.db = self.client[db_name]
            except Exception:
                self.retry_count += 1
                time.sleep(delay)
        if self.db is None:
            raise Exception('Could not connect to MongoDB instance.')
        self.users = self.db["users"]
        self.blocked = self.db["blocked"]
        self.limit = self.db["limit"]
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
        self.rate_limit = rate_limit
        self.messages = get_messages(readable_errors)
        self.penalty = penalty
        self.mail_subject = mail_subject
        self.mail_body = mail_body

    def __del__(self):
        """
        Ensures the MongoDB client is closed when the Auth instance is deleted.
        """
        if hasattr(self, 'client'):
            self.client.close()

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

    def _rate_limit_checker(self, email, ignore_rate_limit):
        """
        Helper to check if a user is rate limited.

        Args:
            email (str): User's email address.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Error message if user is rate limited, None otherwise.
        """
        if self.rate_limit > 0 and not ignore_rate_limit:
            limit = self.limit.find_one({"email": email})
            if limit:
                if limit["last_action"] < time.time():
                    self.limit.update_one({"email": email}, {"$set": {"last_action": time.time()}})
                if time.time() - limit["last_action"] < self.rate_limit:
                    self.limit.update_one({
                        "email": email}, {
                        "$set": {"last_action": int(time.time()) + self.penalty}})
                    return True
            else:
                self.limit.insert_one({"email": email, "last_action": time.time()})
        return False

    def register_user_no_verif(self, email, password, custom_data=None,
                               ignore_rate_limit=False):
        """
        registers a user without email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

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
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
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

    def reset_password_no_verif(self, email, old_password, new_password,
                                ignore_rate_limit=False):
        """
        resets a user's password without email verification

        Args:
            email (str): User's email address.
            old_password (str): User's current password.
            new_password (str): New password.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if not check_password(user, old_password):
                return {"success": False, "message": self.messages["invalid_old_pass"]}
            hashed_password = hash_password(new_password)
            self.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
            return {"success": True, "message": self.messages["password_reset_success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def change_email_no_verif(self, email, new_email, password,
                              ignore_rate_limit=False):
        """
        resets a user's email without previous email verification

        Args:
            email (str): User's email address.
            new_email (str): User's new email.
            password (str): password.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if self.users.find_one({"email": new_email}):
                return {"success": False, "message": self.messages["user_exists"]}
            if not check_password(user, password):
                return {"success": False, "message": self.messages["invalid_pass"]}
            self.users.update_one({"email": email}, {"$set": {"email": new_email}})
            return {"success": True, "message": self.messages["success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def register_user(self, email, password, custom_data=None,
                      ignore_rate_limit=False):
        """
        registers a user with email verification

        Args:
            email (str): User's email address.
            password (str): User's password.
            custom_data: Custom data to save with the user.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

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
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}

            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": self.messages["user_blocked"]}
                else:
                    self.blocked.insert_one({"email": email, "blocked": False})
            hashed_password = hash_password(password)
            verification_code = generate_secure_code()
            send_verification_email(self.mail_info, email, verification_code,
                                    self.mail_subject, self.mail_body)
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

    def register_user_no_pass(self, email, custom_data=None,
                              ignore_rate_limit=False):
        """
        registers a user without password and instead uses email verification.

        Args:
            email (str): User's email address.
            custom_data: Custom data to save with the user.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

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
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}

            if self.blocking:
                blocked_user = self._find_blocked_user(email)
                if blocked_user:
                    if blocked_user["blocked"]:
                        return {"success": False, "message": self.messages["user_blocked"]}
                else:
                    self.blocked.insert_one({"email": email, "blocked": False})
            verification_code = generate_secure_code()
            send_verification_email(self.mail_info, email, verification_code,
                                    self.mail_subject, self.mail_body)
            self.users.insert_one(
                {
                    "email": email,
                    "password": None,
                    "verification_code": verification_code,
                    "blocked": False,
                    "verified": False,
                    "custom_data": custom_data
                }
            )
            return {"success": True, "message": self.messages["verification_code_sent"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_user(self, email, code, ignore_rate_limit=False):
        """
        verifies a user's email using a verification code.

        Args:
            email (str): User's email address.
            code (str): Verification code.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            output = self._block_checker(email, user)
            if output:
                return output
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if user["verification_code"] == code:
                self.users.update_one({"email": email}, {"$set": {"verified": True,
                                                                  "verification_code": None}})
                return {"success": True, "message": self.messages["user_verified"]}
            return {"success": False, "message": self.messages["invalid_reset"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def authenticate_user(self, email, password, mfa=False,
                          ignore_rate_limit=False):
        """
        authenticates a user

        Args:
            email (str): User's email address.
            password (str): User's password.
            mfa (bool): Enable multi-factor authentication.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

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
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if check_password(user, password):
                if mfa:
                    verification_code = generate_secure_code()
                    self.users.find_one_and_update(
                        {"email": email},
                        {"$set": {"verification_code": verification_code}}
                    )
                    send_verification_email(self.mail_info, email, verification_code,
                                            self.mail_subject, self.mail_body)
                return {"success": True, "message": self.messages["authentication_success"]}
            return {"success": False, "message": self.messages["invalid_creds"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_mfa_code(self, email, code, ignore_rate_limit=False):
        """
        verifies a user's MFA code

        Args:
            email (str): User's email address.
            code (str): MFA code.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            output = self._block_checker(email, user)
            if output:
                return output
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if user["verification_code"] == code:
                self.users.update_one({"email": email}, {"$set": {"verification_code": None}})
                return {"success": True, "message": self.messages["mfa_success"]}
            return {"success": False, "message": self.messages["invalid_mfa_code"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def delete_user(self, email, password, del_from_blocking=True, ignore_rate_limit=False):
        """
        deletes a user account

        Args:
            email (str): User's email address.
            password (str): User's password.
            del_from_blocking (bool): Delete the user from the blocked database.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
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

    def delete_user_with_verif(self, email, password, code,
                               del_from_blocking=True,
                               ignore_rate_limit=False):
        """
        deletes a user account

        Args:
            email (str): User's email address.
            password (str): User's password.
            code (str): Verification code.
            del_from_blocking (bool): Delete the user from the blocked database.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self._find_user(email)
            blocked_user = self._find_blocked_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if not check_password(user, password):
                return {"success": False, "message": self.messages["invalid_pass"]}
            if user.get("verification_code") != code:
                return {"success": False, "message": self.messages["invalid_reset"]}
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

    def generate_code(self, email, ignore_rate_limit=False):
        """
        Generates a code and sends it to the user's email.

        Args:
            email (str): User's email address.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        if not self.mail_info:
            raise ValueError("Mail server information is required for reset codes.")
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            reset_code = generate_secure_code()
            self.users.update_one({"email": email}, {"$set": {"verification_code": reset_code}})
            send_verification_email(self.mail_info, email, reset_code,
                                    self.mail_subject, self.mail_body)
            return {"success": True, "message": self.messages["verification_code_sent"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_reset_code_and_reset_password(self, email, reset_code, new_password,
                                             ignore_rate_limit=False):
        """
        verifies a reset code and resets the user's password

        Args:
            email (str): User's email address.
            reset_code (str): Reset code.
            new_password (str): New password.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if user.get("verification_code") != reset_code:
                return {"success": False, "message": self.messages["invalid_reset"]}
            hashed_password = hash_password(new_password)
            self.users.update_one(
                {"email": email}, {"$set": {"password": hashed_password, "verification_code": None}}
            )
            return {"success": True, "message": self.messages["password_reset_success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}

    def verify_reset_code_and_change_email(self, email, reset_code, new_email,
                                           password=None, ignore_rate_limit=False):
        """
        verifies a reset code and changes the user's email

        Args:
            email (str): User's email address.
            reset_code (str): Reset code.
            new_email (str): New email address.
            password (str, optional): User's password for verification if included.
            ignore_rate_limit (bool): Ignore rate limiting for this action.

        Returns:
            dict: Success status and message.
        """
        try:
            user = self.users.find_one({"email": email})
            user_info = self._find_user(email)
            if not user:
                return {"success": False, "message": self.messages["user_not_found"]}
            if self._rate_limit_checker(email, ignore_rate_limit):
                return {"success": False, "message": self.messages["rate_limited"]}
            if self.users.find_one({"email": new_email}):
                return {"success": False, "message": self.messages["user_exists"]}
            if user.get("verification_code") != reset_code:
                return {"success": False, "message": self.messages["invalid_reset"]}
            if password:
                if not check_password(user_info, password):
                    return {"success": False, "message": self.messages["invalid_pass"]}

            self.users.update_one(
                {"email": email}, {"$set": {"email": new_email, "verification_code": None}}
            )
            return {"success": True, "message": self.messages["success"]}
        except Exception as error:
            return {"success": False, "message": str(error)}
