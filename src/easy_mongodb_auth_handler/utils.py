"""
This module provides utility functions for managing user accounts in a MongoDB database.
"""

import time
from pymongo import MongoClient
import certifi
from .package_functions.message import get_messages


class Utils:
    """
    A utility class for managing user account
    - statuses and data in a MongoDB database.
    """

    def __init__(self, mongo_uri, db_name, readable_errors,
                 attempts=6, delay=10, timeout=5000,
                 certs=certifi.where()):
        """
        Initializes the Utils class to connect to a MongoDB instance.
        This class provides methods to manage user accounts, including blocking,
        unblocking, and checking user status.

        Args:
            mongo_uri (str): MongoDB connection URI.
            db_name (str): Name of the database to connect to.
            readable_errors (bool): If True, returns user-friendly error messages.
            attempts (int): Number of connection attempts before giving up.
            delay (int): Delay in seconds between connection attempts.
            timeout (int): Timeout for server selection in milliseconds.
            certs (str): Path to the CA certificates file for TLS connections.

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
