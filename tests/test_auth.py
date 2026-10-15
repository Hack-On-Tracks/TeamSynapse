import os
import pytest
from backend.auth.users_db import hash_password, verify_password, UsersDatabase
from backend.auth.auth import create_access_token, decode_access_token
from backend.storage.storage import DuckDBStorage


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test_auth.db")
    storage = DuckDBStorage(db_path=db_file)
    db = UsersDatabase(storage=storage)
    yield db
    db.close()


def test_password_hashing():
    pw = "SuperSecurePassword123!"
    pw_hash, salt = hash_password(pw)
    assert pw_hash != pw
    assert len(salt) > 0
    assert verify_password(pw, pw_hash, salt) is True
    assert verify_password("WrongPassword", pw_hash, salt) is False


def test_user_creation_and_auth(temp_db):
    user = temp_db.create_user("analyst1", "password123", full_name="SOC Analyst", role="analyst")
    assert user["username"] == "analyst1"
    assert user["role"] == "analyst"

    # Authenticate with valid password
    auth_user = temp_db.authenticate("analyst1", "password123")
    assert auth_user is not None
    assert auth_user["username"] == "analyst1"

    # Authenticate with invalid password
    bad_auth = temp_db.authenticate("analyst1", "wrongpass")
    assert bad_auth is None

    # Check audit log recorded events
    logs = temp_db.get_audit_logs()
    assert len(logs) >= 2


def test_jwt_generation_and_decoding():
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    assert isinstance(token, str)
    decoded = decode_access_token(token)
    assert decoded["sub"] == "admin"
    assert decoded["role"] == "admin"
