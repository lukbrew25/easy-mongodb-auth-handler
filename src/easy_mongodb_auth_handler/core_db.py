"""
This module provides the CoreDB class for
- managing MongoDB connections, collections, and the database.
"""

import time
import os
from pymongo import MongoClient
import certifi
from dotenv import load_dotenv
from .package_functions.message import get_messages


class CoreDB:
    """
    CoreDB class for managing MongoDB connections, collections, and the database.
    """

    def __init__(self, conf_file=None, mongo_uri=None,
                 db_name=None, readable_errors=True,
                 db_attempts=6, db_delay=10, db_timeout=5000,
                 certs=certifi.where()):
        """
        Initializes the CoreDB class to connect to a MongoDB instance.

        Args:
            conf_file (str, optional): Path to a .env configuration file.
            mongo_uri (str, optional): MongoDB connection URI.
            db_name (str, optional): Name of the database to connect to.
            readable_errors (bool, optional): If True, returns user-friendly error messages.
            db_attempts (int, optional): Number of connection attempts before giving up.
            db_delay (int, optional): Delay in seconds between connection attempts.
            db_timeout (int, optional): Timeout for server selection in milliseconds.
            certs (str, optional): Path to the CA certificates file for TLS connections.

        Raises:
            ValueError: If attempts < 1 or delay < 0.
            Exception: If unable to connect to the MongoDB instance after the specified attempts.
        """
        if not mongo_uri or not db_name:
            if conf_file:
                load_dotenv(conf_file)
            elif os.path.exists(".emdb_coredb"):
                load_dotenv(".emdb_coredb")
            else:
                raise ValueError("Missing info and configuration "
                                 "file not found or not provided.")
            mongo_uri = os.getenv("MONGO_URI", None)
            db_name = os.getenv("DB_NAME", None)
            readable_errors = bool(os.getenv("READABLE_ERRORS"))
            db_attempts = int(os.getenv("DB_ATTEMPTS", 1))
            db_delay = int(os.getenv("DB_DELAY", 10))
            db_timeout = int(os.getenv("DB_TIMEOUT", 5000))
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
