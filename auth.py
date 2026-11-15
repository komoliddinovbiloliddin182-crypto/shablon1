"""Autentifikatsiya: ro'yxatdan o'tish, kirish, sessiya va FastAPI dependency'lar.

Muhim qoida: platformada ro'yxatdan o'tgan BIRINCHI foydalanuvchi avtomatik
administrator bo'ladi. Qolganlari oddiy foydalanuvchi (o'z botlarini ko'radi va
o'chiradi, lekin boshqalarning botlarini ko'ra olmaydi).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db import count_users, db, db_lock

bearer_scheme = HTTPBearer(auto_error=False)
SESSION_DURATION = timedelta(days=30)
USERNAME_RE = "^[A-Za-z0-9_]{3,30}$"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


async def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires = now + SESSION_DURATION
    async with db_lock:
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(), expires.isoformat()),
        )
        db.commit()
    return token


async def register_user(username: str, password: str) -> dict:
    """Yangi foydalanuvchi yaratadi. Birinchisi admin bo'ladi."""
    now = datetime.utcnow()
    is_admin = 1 if count_users() == 0 else 0
    async with db_lock:
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            raise ValueError("Bu foydalanuvchi nomi band.")
        cur = db.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), is_admin, now.isoformat()),
        )
        db.commit()
        user_id = cur.lastrowid
    token = await create_session(user_id)
    return {"user_id": user_id, "username": username, "is_admin": bool(is_admin), "token": token}


async def login_user(username: str, password: str) -> dict:
    async with db_lock:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("Foydalanuvchi nomi yoki parol noto'g'ri.")
    token = await create_session(row["id"])
    return {"user_id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"]), "token": token}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Any:
    """Bearer token orqali joriy foydalanuvchini qaytaradi."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tizimga kirilmagan.")
    token = credentials.credentials
    async with db_lock:
        row = db.execute(
            """SELECT u.id, u.username, u.is_admin, u.created_at, s.expires_at
               FROM sessions s JOIN users u ON s.user_id = u.id
               WHERE s.token=?""",
            (token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessiya topilmadi. Qayta kiring.")
        if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]):
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessiya muddati tugagan.")
    return row


async def require_admin(user: Any = Depends(get_current_user)) -> Any:
    if not user["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator huquqi kerak.")
    return user
