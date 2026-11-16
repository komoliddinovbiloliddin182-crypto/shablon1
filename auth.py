"""Autentifikatsiya: ro'yxatdan o'tish, kirish, sessiya va FastAPI dependency'lar.

Sayt admini: platforma ishga tushganda avtomatik yaratiladigan doimiy admin hisobi.
  • Login:    ADMIN_USERNAME  (standart: admin)
  • Parol:    ADMIN_PASSWORD  (standart: BILOLIDDIN)
Bu hisob Render muhit o'zgaruvchilari orqali o'zgartirilishi mumkin, lekin hech qachon
o'chirilmaydi va bloklanmaydi. Oddiy foydalanuvchilar ro'yxatdan o'tadi va o'z botlarini
boshqaradi; admin esa butun platformani boshqaradi.
"""
from __future__ import annotations

import os
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

# Doimiy sayt adminining ma'lumotlari (muhit o'zgaruvchilari orqali o'zgartiriladi).
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "BILOLIDDIN")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


async def ensure_admin_account() -> None:
    """Sayt adminini kafolatlaydi: agar yo'q bo'lsa, yaratadi yoki parolini yangilaydi.

    Platforma har safar ishga tushganda chaqiriladi. Agar admin hisobi o'chirilgan
    bo'lsa yoki paroli muhitdan o'zgartirilgan bo'lsa, bu funksiya uni tiklaydi.
    """
    async with db_lock:
        row = db.execute("SELECT id FROM users WHERE username=?", (ADMIN_USERNAME,)).fetchone()
        hashed = hash_password(ADMIN_PASSWORD)
        if row:
            # Admin hisobi mavjud — admin huquqi va parolini kafolatlaymiz, blokni yechamiz.
            db.execute(
                "UPDATE users SET password_hash=?, is_admin=1, is_blocked=0 WHERE id=?",
                (hashed, row["id"]),
            )
        else:
            db.execute(
                "INSERT INTO users (username, password_hash, is_admin, is_blocked, created_at) "
                "VALUES (?, ?, 1, 0, ?)",
                (ADMIN_USERNAME, hashed, datetime.utcnow().isoformat()),
            )
        db.commit()


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
    """Yangi oddiy foydalanuvchi yaratadi (admin emas). Sayt adminining login'i band."""
    if username == ADMIN_USERNAME:
        raise ValueError("Bu foydalanuvchi nomi band.")
    now = datetime.utcnow()
    async with db_lock:
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            raise ValueError("Bu foydalanuvchi nomi band.")
        cur = db.execute(
            "INSERT INTO users (username, password_hash, is_admin, is_blocked, created_at) "
            "VALUES (?, ?, 0, 0, ?)",
            (username, hash_password(password), now.isoformat()),
        )
        db.commit()
        user_id = cur.lastrowid
    token = await create_session(user_id)
    return {"user_id": user_id, "username": username, "is_admin": False, "token": token}


async def login_user(username: str, password: str) -> dict:
    async with db_lock:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("Foydalanuvchi nomi yoki parol noto'g'ri.")
    if row["is_blocked"]:
        raise ValueError("Hisobingiz vaqtincha bloklangan. Administratorga murojaat qiling.")
    token = await create_session(row["id"])
    return {"user_id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"]), "token": token}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Any:
    """Bearer token orqali joriy foydalanuvchini qaytaradi. Bloklanganlar rad etiladi."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tizimga kirilmagan.")
    token = credentials.credentials
    async with db_lock:
        row = db.execute(
            """SELECT u.id, u.username, u.is_admin, u.is_blocked, u.balance,
                      u.ever_created_bot, u.created_at, s.expires_at
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
        if row["is_blocked"]:
            # Bloklangan foydalanuvchining sessiyasini darhol o'chiramiz.
            db.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
            db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hisobingiz bloklangan.")
    return row


async def require_admin(user: Any = Depends(get_current_user)) -> Any:
    if not user["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator huquqi kerak.")
    return user
