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
        """Set up the test environment with a mocked MongoDB client."""
        self.patcher = patch("src.easy_mongodb_auth_handler.auth.MongoClient", autospec=True)
        self.mock_mongo_client = self.patcher.start()
        self.mock_db = MagicMock()
        self.mock_mongo_client.return_value.__getitem__.return_value = self.mock_db
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

    def tearDown(self):
        """Stop the patcher after each test."""
        self.patcher.stop()

    def test_register_user_no_verif_success(self):
        """Test registering a user without verification (success case)."""
        self.mock_db["users"].find_one.return_value = None
        self.mock_db["users"].insert_one.return_value = None
        result = self.auth.register_user_no_verif("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User registered without verification.")

    def test_register_user_no_verif_existing_user(self):
        """Test registering a user without verification (user already exists)."""
        self.mock_db["users"].find_one.return_value = {"email": "test@example.com"}
        result = self.auth.register_user_no_verif("test@example.com", "password123")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "User already exists.")

    def test_reset_password_no_verif_success(self):
        """Test resetting a password without verification (success case)."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("oldpassword"),
        }
        result = self.auth.reset_password_no_verif(
            "test@example.com", "oldpassword", "newpassword"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Password reset successful.")

    def test_reset_password_no_verif_invalid_old_password(self):
        """Test resetting a password without verification (invalid old password)."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("oldpassword"),
        }
        result = self.auth.reset_password_no_verif(
            "test@example.com", "wrongpassword", "newpassword"
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid old password.")

    def test_verify_user_success(self):
        """Test verifying a user with a valid verification code."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "verification_code": "123456",
        }
        result = self.auth.verify_user("test@example.com", "123456")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User verified.")

    def test_verify_user_invalid_code(self):
        """Test verifying a user with an invalid verification code."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "verification_code": "123456",
        }
        result = self.auth.verify_user("test@example.com", "654321")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid verification code.")

    def test_authenticate_user_success(self):
        """Test authenticating a user with valid credentials."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
            "verified": True,
        }
        result = self.auth.authenticate_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Authentication successful.")

    def test_authenticate_user_invalid_credentials(self):
        """Test authenticating a user with invalid credentials."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
            "verified": True,
        }
        result = self.auth.authenticate_user("test@example.com", "wrongpassword")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid credentials.")

    def test_delete_user_success(self):
        """Test deleting a user with valid credentials."""
        self.mock_db["users"].find_one.return_value = {
            "email": "test@example.com",
            "password": hash_password("password123"),
        }
        self.mock_db["users"].delete_one.return_value.deleted_count = 1
        result = self.auth.delete_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User deleted.")

    @patch("src.easy_mongodb_auth_handler.auth.send_verification_email", autospec=True)
    def test_generate_reset_code_success(self, mock_send_email):
        """Test generating a reset code for a user."""
        self.mock_db["users"].find_one.return_value = {"email": "test@example.com"}
        self.mock_db["users"].update_one.return_value = None
        mock_send_email.return_value = None  # Mock the email sending
        result = self.auth.generate_reset_code("test@example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Reset code sent to email.")
        mock_send_email.assert_called_once_with(
            self.auth.mail_info, "test@example.com", unittest.mock.ANY
        )

    @patch("src.easy_mongodb_auth_handler.auth.send_verification_email", autospec=True)
    def test_register_user_with_verification(self, mock_send_email):
        """Test registering a user with email verification."""
        self.mock_db["users"].find_one.return_value = None
        self.mock_db["users"].insert_one.return_value = None
        mock_send_email.return_value = None  # Mock the email sending
        result = self.auth.register_user("test@example.com", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User registered. Verification email sent.")
        mock_send_email.assert_called_once_with(
            self.auth.mail_info, "test@example.com", unittest.mock.ANY
        )

    def test_verify_reset_code_and_reset_password_success(self):
        """Test verifying a reset code and resetting the password (success case)."""
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

    def test_verify_reset_code_and_reset_password_invalid_code(self):
        """Test verifying a reset code and resetting the password (invalid code)."""
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
