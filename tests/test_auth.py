"""
Unit tests for the easy_mongodb_auth_handler package.
"""

import unittest
from unittest.mock import patch, MagicMock
from src.easy_mongodb_auth_handler.auth import Auth
from src.easy_mongodb_auth_handler.utils import (
    validate_email,
    hash_password,
    verify_password,
    generate_secure_code,
    send_verification_email,
)


class TestUtils(unittest.TestCase):
    """Tests for utility functions."""

    def test_validate_email(self):
        """Test the validate_email function with valid and invalid emails."""
        self.assertTrue(validate_email("valid.email@example.com"))
        self.assertFalse(validate_email("invalid-email"))

    def test_hash_and_verify_password(self):
        """Test hashing and verifying passwords."""
        password = "securepassword"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))

    def test_generate_secure_code(self):
        """Test generating a secure alphanumeric code."""
        code = generate_secure_code(8)
        self.assertEqual(len(code), 8)
        self.assertTrue(code.isalnum())

    @patch("src.easy_mongodb_auth_handler.utils.smtplib.SMTP")
    def test_send_verification_email(self, mock_smtp):
        """Test sending a verification email."""
        mock_smtp.return_value = MagicMock()
        mail_info = {
            "server": "smtp.example.com",
            "port": 587,
            "username": "test@example.com",
            "password": "password",
        }
        send_verification_email(mail_info, "recipient@example.com", "123456")
        mock_smtp.assert_called_once()


class TestAuth(unittest.TestCase):
    """Tests for the Auth class."""

    def setUp(self):
        """Set up the test environment."""
        self.mock_db = MagicMock()
        self.auth = Auth(
            "mongodb://localhost:27017",
            "test_db",
            mail_info={
                "server": "smtp.example.com",
                "port": 587,
                "username": "test@example.com",
                "password": "password",
            },
        )

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_register_user_no_verif_success(self, mock_mongo_client):
        """Test registering a user without verification (success case)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = None
        self.mock_db["users"].insert_one.return_value = None
        result = self.auth.register_user_no_verif("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User registered without verification.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_register_user_no_verif_existing_user(self, mock_mongo_client):
        """Test registering a user without verification (user already exists)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {"email": "test@example.com"}
        result = self.auth.register_user_no_verif("test@example.com", "password123")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "User already exists.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_reset_password_no_verif_success(self, mock_mongo_client):
        """Test resetting a password without verification (success case)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("oldpassword"),
        }
        result = self.auth.reset_password_no_verif(
            "test@example.com", "oldpassword", "newpassword"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Password reset successful.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_reset_password_no_verif_invalid_old_password(self, mock_mongo_client):
        """Test resetting a password without verification (invalid old password)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("oldpassword"),
        }
        result = self.auth.reset_password_no_verif(
            "test@example.com", "wrongpassword", "newpassword"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid old password.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    @patch("src.easy_mongodb_auth_handler.utils.smtplib.SMTP")
    def test_register_user_with_verification(self, mock_smtp, mock_mongo_client):
        """Test registering a user with email verification."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = None
        self.mock_db["users"].insert_one.return_value = None
        mock_smtp.return_value = MagicMock()
        result = self.auth.register_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User registered. Verification email sent.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_verify_user_success(self, mock_mongo_client):
        """Test verifying a user with a valid verification code."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "verification_code": "123456",
        }
        result = self.auth.verify_user("test@example.com", "123456")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User verified.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_verify_user_invalid_code(self, mock_mongo_client):
        """Test verifying a user with an invalid verification code."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "verification_code": "123456",
        }
        result = self.auth.verify_user("test@example.com", "654321")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid verification code.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_authenticate_user_success(self, mock_mongo_client):
        """Test authenticating a user with valid credentials."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
            "verified": True,
        }
        result = self.auth.authenticate_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Authentication successful.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_authenticate_user_invalid_credentials(self, mock_mongo_client):
        """Test authenticating a user with invalid credentials."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
            "verified": True,
        }
        result = self.auth.authenticate_user("test@example.com", "wrongpassword")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid credentials.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_delete_user_success(self, mock_mongo_client):
        """Test deleting a user with valid credentials."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
        }
        self.mock_db["users"].delete_one.return_value.deleted_count = 1
        result = self.auth.delete_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User deleted.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    @patch("src.easy_mongodb_auth_handler.utils.smtplib.SMTP")
    def test_generate_reset_code_success(self, mock_smtp, mock_mongo_client):
        """Test generating a reset code for a user."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {"email": "test@example.com"}
        self.mock_db["users"].update_one.return_value = None
        mock_smtp.return_value = MagicMock()
        result = self.auth.generate_reset_code("test@example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Reset code sent to email.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_verify_reset_code_and_reset_password_success(self, mock_mongo_client):
        """Test verifying a reset code and resetting the password (success case)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "reset_code": "123456",
        }
        self.mock_db["users"].update_one.return_value = None
        result = self.auth.verify_reset_code_and_reset_password(
            "test@example.com", "123456", "newpassword"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Password reset successful.")

    @patch("src.easy_mongodb_auth_handler.auth.MongoClient")
    def test_verify_reset_code_and_reset_password_invalid_code(self, mock_mongo_client):
        """Test verifying a reset code and resetting the password (invalid code)."""
        mock_mongo_client.return_value = MagicMock()
        mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "reset_code": "123456",
        }
        result = self.auth.verify_reset_code_and_reset_password(
            "test@example.com", "654321", "newpassword"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid reset code.")


if __name__ == "__main__":
    unittest.main()
