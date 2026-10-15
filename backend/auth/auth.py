import os
import datetime
from typing import Optional
from fastapi import Header, HTTPException, status
import jwt
from jwt import PyJWTError

# Load secret and algorithm from env (at least 32 bytes for secure HMAC-SHA256)
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecretkey_ciphersentinel_soc_defense_token_signing_key_2026')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '60'))


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: Optional[str] = Header(None, alias="Authorization")):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raw_token = token[7:].strip() if token.lower().startswith("bearer ") else token.strip()
    try:
        payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation error: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Re-export database utilities for convenience
from .users_db import UsersDatabase, hash_password, verify_password
