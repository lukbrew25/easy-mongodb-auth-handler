"""
This module provides the CoreDB class for
- managing MongoDB connections, collections, and the database.
"""

import time
from pymongo import MongoClient
import certifi
from .package_functions.message import get_messages


class CoreDB:
    """
    CoreDB class for managing MongoDB connections, collections, and the database.
    """

    def __init__(self, mongo_uri, db_name, readable_errors,
                 attempts=6, delay=10, timeout=5000,
                 certs=certifi.where()):
        """
        Initializes the CoreDB class to connect to a MongoDB instance.

        Args:
            mongo_uri (str): MongoDB connection URI.
            db_name (str): Name of the database to connect to.
            readable_errors (bool): If True, returns user-friendly error messages.
            attempts (int): Number of connection attempts before giving up.
            delay (int): Delay in seconds between connection attempts.
            timeout (int): Timeout for server selection in milliseconds.
            certs (str): Path to the CA certificates file for TLS connections.

        Raises:
            ValueError: If attempts < 1 or delay < 0.
            Exception: If unable to connect to the MongoDB instance after the specified attempts.
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
        self.messages = get_messages(readable_errors)

    def __del__(self):
        """
        Ensures the MongoDB client is closed when the CoreDB instance is deleted.
        """
        if hasattr(self, 'client'):
            self.client.close()

    def remove_users_collection(self):
        """
        Removes the users collection from the database.
        """
        self.db.drop_collection("users")

    def remove_blocked_collection(self):
        """
        Removes the blocked collection from the database.
        """
        self.db.drop_collection("blocked")

    def remove_limit_collection(self):
        """
        Removes the limit collection from the database.
        """
        self.db.drop_collection("limit")

    def remove_all_collections(self):
        """
        Removes users, blocked, and limit collections from the database.
        """
        self.remove_users_collection()
        self.remove_blocked_collection()
        self.remove_limit_collection()

    def create_users_collection(self):
        """
        Creates the users collection in the database.
        """
        self.users = self.db["users"]

    def create_blocked_collection(self):
        """
        Creates the blocked collection in the database.
        """
        self.blocked = self.db["blocked"]

    def create_limit_collection(self):
        """
        Creates the limit collection in the database.
        """
        self.limit = self.db["limit"]

    def create_all_collections(self):
        """
        Creates both users and blocked collections in the database.
        """
        self.create_users_collection()
        self.create_blocked_collection()
        self.create_limit_collection()

    def reset_users_collection(self):
        """
        Resets the users collection by dropping it and creating a new one.
        """
        self.remove_users_collection()
        self.create_users_collection()

    def reset_blocked_collection(self):
        """
        Resets the blocked collection by dropping it and creating a new one.
        """
        self.remove_blocked_collection()
        self.create_blocked_collection()

    def reset_limit_collection(self):
        """
        Resets the limit collection by dropping it and creating a new one.
        """
        self.remove_limit_collection()
        self.create_limit_collection()

    def reset_all_collections(self):
        """
        Resets both users and blocked collections.
        """
        self.reset_users_collection()
        self.reset_blocked_collection()
        self.reset_limit_collection()

    def remove_db(self):
        """
        Removes the entire database.
        """
        self.client.drop_database(self.db.name)

    def create_db(self):
        """
        Creates the database
        """
        self.db = self.client[self.db.name]

    def reset_db(self):
        """
        Resets the entire database.
        """
        self.remove_db()
        self.create_db()
        self.create_all_collections()

    def user_count(self):
        """
        Returns the count of users in the users collection.

        Returns:
            int: Number of users in the users collection.
        """
        return int(self.users.count_documents({}))

    def db_data_size(self):
        """
        Returns the size of the database in bytes.

        Returns:
            int: Size of the database in bytes.
        """
        return int(self.db.command("dbStats")["dataSize"])

    def db_storage_size(self):
        """
        Returns the total storage size of the database in bytes.

        Returns:
            int: Total storage size of the database in bytes.
        """
        return int(self.db.command("dbStats")["storageSize"])

    def db_index_size(self):
        """
        Returns the size of the indexes in the database in bytes.

        Returns:
            int: Size of the indexes in bytes.
        """
        return int(self.db.command("dbStats")["indexSize"])

    def db_raw_stats(self):
        """
        Returns raw statistics of the database.

        Returns:
            dict: Raw statistics of the database.
        """
        return self.db.command("dbStats")
