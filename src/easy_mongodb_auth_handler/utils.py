"""
This module provides utility functions for managing user accounts in a MongoDB database.
"""

import time
import os
from pymongo import MongoClient
import certifi
from dotenv import load_dotenv
from .package_functions.message import get_messages


class Utils:
    """
    A utility class for managing user account
    - statuses and data in a MongoDB database.
    """

    def __init__(self, conf_file=None, mongo_uri=None,
                 db_name=None, readable_errors=True,
                 db_attempts=6, db_delay=10, db_timeout=5000,
                 certs=certifi.where()):
        """
        Initializes the Utils class to connect to a MongoDB instance.
        This class provides methods to manage user accounts, including blocking,
        unblocking, and checking user status.

        Args:
            conf_file (str, optional): Path to a .env configuration file.
            mongo_uri (str, optional): MongoDB connection URI.
            db_name (str, optional): Name of the database to connect to.
            readable_errors (bool, optional): If True, returns user-friendly error messages.
            db_attempts (int, optional): Number of connection attempts before giving up.
            db_delay (int, optional): Delay in seconds between connection attempts.
            db_timeout (int, optional): Timeout for server selection in milliseconds.
            certs (str, optional): Path to the CA certificates file for TLS connections.

        """
        if not mongo_uri or not db_name:
            if conf_file:
                load_dotenv(conf_file)
            elif os.path.exists(".emdb_utils"):
                load_dotenv(".emdb_utils")
            else:
                raise ValueError("Missing info and configuration "
                                 "file not found or not provided.")
            mongo_uri = os.getenv("MONGO_URI", None)
            db_name = os.getenv("DB_NAME", None)
            readable_errors = bool(os.getenv("READABLE_ERRORS"))
            db_attempts = int(os.getenv("DB_ATTEMPTS", "1"))
            db_delay = int(os.getenv("DB_DELAY", "10"))
            db_timeout = int(os.getenv("DB_TIMEOUT", "5000"))
            certs = os.getenv("CERTS", certifi.where())
        if not mongo_uri or not db_name:
            raise ValueError("MongoDB URI and DB name must be provided.")
        self.db = None
        self.retry_count = 0
        if db_attempts < 1:
            raise ValueError("Number of attempts must be at least 1.")
        if db_delay < 0:
            raise ValueError("Delay must be a non-negative integer.")
        self.max_retries = db_attempts
        while self.db is None and self.retry_count < self.max_retries:
            try:
                self.client = MongoClient(mongo_uri,
                                          serverSelectionTimeoutMS=db_timeout,
                                          tlsCAFile=certs
                                          )
                self.db = self.client[db_name]
            except Exception:
                self.retry_count += 1
                time.sleep(db_delay)
        if self.db is None:
            raise Exception('Could not connect to MongoDB instance.')
        self.users = self.db["users"]
        self.blocked = self.db["blocked"]
        self.limit = self.db["limit"]
        self.messages = get_messages(readable_errors)

    def __del__(self):
        """
        Ensures the MongoDB client is closed when the Utils instance is deleted.
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

    def time_since_request(self, email):
        """
        Checks the time since the last request for a user.

        Args:
            email (str): User's email address.

        Returns:
            int: Time in seconds since the last request, or -1 if not found/error.
        """
        try:
            limit = self.limit.find_one({"email": email})
            if limit:
                last_request_time = limit.get("last_action")
                if last_request_time:
                    time_since = time.time() - last_request_time
                    return int(time_since)
            return -1
        except Exception:
            return -1

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
                return {"success": True, "message": self.messages["user_not_found"]}
            if blocked_user["blocked"]:
                return {"success": True, "message": self.messages["user_blocked"]}
            return {"success": False, "message": self.messages["not_blocked"]}
        except Exception as error:
            return {"success": True, "message": str(error)}

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
