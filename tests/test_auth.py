"""Unit tests for PrivacyGuard X User Authentication."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.database import (
    create_user,
    authenticate_user,
    hash_password,
    verify_password
)


def test_password_hashing():
    pwd = "SecurePassword123!"
    p_hash, salt = hash_password(pwd)
    assert p_hash is not None
    assert salt is not None
    assert verify_password(pwd, salt, p_hash) is True
    assert verify_password("WrongPassword!", salt, p_hash) is False


def test_create_and_authenticate_user():
    import uuid
    uid = uuid.uuid4().hex[:8]
    test_user = f"user_{uid}"
    test_email = f"{test_user}@test.com"
    test_pwd = "MySecretPassword2026!"

    ok, msg = create_user(
        username=test_user,
        email=test_email,
        password=test_pwd,
        full_name="Test User"
    )
    assert ok is True
    assert "successfully" in msg.lower()

    # Authenticate with username
    ok_auth, user_data, auth_msg = authenticate_user(test_user, test_pwd)
    assert ok_auth is True
    assert user_data["username"] == test_user
    assert user_data["email"] == test_email

    # Authenticate with email
    ok_email, _, _ = authenticate_user(test_email, test_pwd)
    assert ok_email is True

    # Bad password
    bad_auth, _, _ = authenticate_user(test_user, "InvalidPassword")
    assert bad_auth is False


def test_duplicate_user_rejection():
    import uuid
    uid = uuid.uuid4().hex[:8]
    test_user = f"dup_{uid}"
    test_email = f"{test_user}@test.com"

    ok1, _ = create_user(test_user, test_email, "Password123!")
    assert ok1 is True

    # Duplicate username
    ok2, err2 = create_user(test_user, f"other_{uid}@test.com", "Password123!")
    assert ok2 is False
    assert "already taken" in err2.lower()
