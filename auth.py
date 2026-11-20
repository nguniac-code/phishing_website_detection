"""Account validation, password hashing, and administrator bootstrap command."""

import argparse
import base64
import hashlib
import getpass
import hmac
import re
import secrets

import database


_ITERATIONS = 310_000
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        _ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored_hash.split("$", 3)
        iterations = int(iteration_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 1_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
    except (AttributeError, ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def validate_registration(
    full_name: str,
    username: str,
    email: str,
    password: str,
    confirm_password: str,
) -> None:
    if not full_name.strip() or len(full_name.strip()) > 100:
        raise ValueError("Enter your full name (up to 100 characters).")
    if not _USERNAME_PATTERN.fullmatch(username.strip()):
        raise ValueError(
            "Username must be 3–32 characters and contain only letters, numbers, '.', '_' or '-'."
        )
    if not _EMAIL_PATTERN.fullmatch(email.strip()) or len(email.strip()) > 254:
        raise ValueError("Enter a valid email address.")
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters.")
    if password != confirm_password:
        raise ValueError("Passwords do not match.")


def register_user(
    full_name: str,
    username: str,
    email: str,
    password: str,
    confirm_password: str,
) -> int:
    validate_registration(full_name, username, email, password, confirm_password)
    database.init_db()
    return database.create_user(
        full_name.strip(),
        username.strip(),
        email.strip().lower(),
        hash_password(password),
    )


def authenticate_user(identifier: str, password: str) -> dict | None:
    database.init_db()
    user = database.get_user_by_identifier(identifier)
    if (
        user is None
        or not user["is_active"]
        or not verify_password(password, user["password_hash"])
    ):
        return None
    return {
        key: user[key]
        for key in ("id", "full_name", "username", "email", "role", "is_active")
    }


def create_admin_interactively() -> None:
    database.init_db()
    full_name = input("Full name: ").strip()
    username = input("Username: ").strip()
    email = input("Email: ").strip()
    password = getpass.getpass("Password (minimum 10 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    validate_registration(full_name, username, email, password, confirmation)
    database.create_user(
        full_name, username, email.lower(), hash_password(password), role="admin"
    )
    print("Administrator account created. Sign in through the application.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishGuard account administration")
    parser.add_argument(
        "command",
        choices=("create-admin",),
        help="Create an administrator account using hidden password prompts.",
    )
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin_interactively()