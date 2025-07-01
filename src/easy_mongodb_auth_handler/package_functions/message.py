"""
    Return message dictionary.
"""


def get_messages(usr_readable):
    """
    Get message dictionary based on user readability preference.

    Args:
        usr_readable: bool

    Returns:
        dict: Messages dictionary with user-friendly or code-based messages.
    """
    if usr_readable:
        messages = {
            "success": "Success",
            "error": "Error",
            "user_not_found": "User not found.",
            "invalid_email": "Invalid email format.",
            "user_exists": "User already exists.",
            "user_blocked": "User is blocked.",
            "verification_code_sent": "Verification email sent.",
            "user_verified": "User verified.",
            "authentication_success": "Authentication successful.",
            "password_reset_success": "Password reset successful.",
            "user_deleted": "User deleted.",
            "user_not_deleted": "Failed to delete user.",
            "data_updated": "Custom user data field updated.",
            "field_not_found": "Field not found.",
            "data_changed": "Custom user data changed.",
            "not_blocked": "User is not blocked.",
            "not_verified": "User is not verified.",
            "user_unblocked": "User unblocked.",
            "invalid_reset": "Invalid code.",
            "not_deleted_blocked": "User deleted but not from blocked database.",
            "not_deleted": "Failed to delete user.",
            "not_deleted_all": "Failed to delete user from all databases.",
            "invalid_old_pass": "Invalid old password.",
            "invalid_pass": "Invalid password.",
            "invalid_creds": "Invalid credentials.",
            "not_found_blocked": "User is not found in blocked database.",
            "rate_limited": "Rate limit exceeded. Please try again later."
        }
    else:
        messages = {
            "success": 200,
            "verification_code_sent": 201,
            "authentication_success": 202,
            "password_reset_success": 203,
            "user_deleted": 204,
            "data_updated": 205,
            "data_changed": 206,
            "user_unblocked": 207,
            "user_verified": 300,
            "not_blocked": 301,
            "not_verified": 302,
            "error": 400,
            "rate_limited": 401,
            "user_exists": 402,
            "user_blocked": 403,
            "user_not_found": 404,
            "user_not_deleted": 410,
            "field_not_found": 412,
            "invalid_reset": 417,
            "not_deleted": 419,
            "not_deleted_blocked": 420,
            "not_deleted_all": 421,
            "not_found_blocked": 423,
            "invalid_old_pass": 500,
            "invalid_pass": 501,
            "invalid_creds": 502,
            "invalid_email": 503
        }
    return messages
