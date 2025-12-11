"""
Allows loading as package.
"""


from .auth import Auth
from .utils import Utils
from .core_db import CoreDB
from .package_functions.message import get_messages
from .package_functions.func import (generate_secure_code, get_version, validate_email,
                                     check_password, hash_password, verify_password)
