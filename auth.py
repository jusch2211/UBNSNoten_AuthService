import jwt
import time
from fastapi import HTTPException, status
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_SECONDS

# DEMO users
USERS = {
    "admin": {"password": "admin", "roles": ["ADMIN"]},
    "user": {"password": "user", "roles": ["USER"]},
}


def authenticate(username: str, password: str):
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user


def create_jwt(username: str, roles: list[str]):
    payload = {
        "sub": username,
        "roles": roles,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt(token: str):
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
