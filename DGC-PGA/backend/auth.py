"""Authentication helpers: bcrypt hashing + JWT tokens."""
import os
import bcrypt
import jwt
import base64
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta

JWT_ALGORITHM = "HS256"
ACCESS_TTL_MIN = 60 * 12  # 12 hours
REFRESH_TTL_DAYS = 7


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id, "email": email, "role": role, "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id, "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])


def create_mfa_token(user_id: str) -> str:
    payload = {"sub": user_id, "type": "mfa",
               "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(_secret().encode()).digest())
    return Fernet(key)


def encrypt_secret(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode()


def decrypt_secret(c: str) -> str:
    return _fernet().decrypt(c.encode()).decode()
