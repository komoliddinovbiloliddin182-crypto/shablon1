"""BotBuilder — FastAPI asosiy ilova.

Imkoniyatlar:
  • Login/parol bilan ro'yxatdan o'tish va kirish (birinchi foydalanuvchi — admin)
  • Bot tokenini ulash va avtomatik ishga tushirish (aiogram polling)
  • Foydalanuvchi o'z botlarini ko'radi va saytdan o'chiradi
  • Admin barcha botlarni ko'radi va boshqaradi
  • Do'kon boti: katalog, savat, buyurtma (ma'lumotlar saqlanadi)
  • Yordam boti: ticket tizimi
  • Quiz boti: 5 savol, natija saqlash
  • Obuna boti: obuna yo'riqnomasi

Render'da: uvicorn main:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from aiogram import Bot
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from auth import (
    USERNAME_RE,
    create_session,
    get_current_user,
    login_user,
    register_user,
    require_admin,
)
from bot_engine import DEFAULT_PRODUCTS, build_dispatcher
from db import count_users, db, db_lock, init_db

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("botbuilder")

BASE_DIR = Path(__file__).resolve().parent

# ── Token shifrlash (Fernet) ──
secret = os.getenv("TOKEN_ENCRYPTION_SECRET")
if not secret:
    local_key_file = BASE_DIR / ".local_encryption_secret"
    if os.getenv("RENDER"):
        raise RuntimeError("TOKEN_ENCRYPTION_SECRET Render muhitida sozlanmagan.")
    if local_key_file.exists():
        secret = local_key_file.read_text(encoding="utf-8").strip()
    else:
        import secrets as _secrets

        secret = _secrets.token_urlsafe(48)
        local_key_file.write_text(secret, encoding="utf-8")
        try:
            local_key_file.chmod(0o600)
        except OSError:
            pass

fernet_key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
cipher = Fernet(fernet_key)

init_db()

VALID_TEMPLATES = {"support", "shop", "quiz", "sub"}
TEMPLATE_LABELS = {
    "support": "Yordam markazi",
    "shop": "Onlayn do'kon",
    "quiz": "Quiz / Test",
    "sub": "Obuna boti",
}

running_bots: dict[str, tuple[asyncio.Task, Bot]] = {}
rate_log: dict[str, deque] = defaultdict(deque)


# ── Yordamchi funksiyalar ──

def encrypt_token(token: str) -> str:
    return cipher.encrypt(token.encode("utf-8")).decode("ascii")


def decrypt_token(value: str) -> str:
    return cipher.decrypt(value.encode("ascii")).decode("utf-8")


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_valid_trial(row) -> bool:
    try:
        return bool(row["is_active"]) and datetime.utcnow() < datetime.fromisoformat(row["trial_ends_at"])
    except (ValueError, TypeError):
        return False


def allow_create(ip: str) -> bool:
    now = time.time()
    q = rate_log[ip]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= 10:
        return False
    q.append(now)
    return True


# ── Botni ishga tushirish / to'xtatish ──

async def run_bot(token: str, template: str, bot_id: int) -> None:
    td = token_digest(token)
    existing = running_bots.get(token)
    if existing and not existing[0].done():
        return
    bot = Bot(token=token)
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        dp = build_dispatcher(token, template, bot_id, td)
        async def poll():
            try:
                await dp.start_polling(bot, handle_signals=False, close_bot_session=False)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Telegram polling to'xtadi: %s", td[:10])
            finally:
                await bot.session.close()
        task = asyncio.create_task(poll(), name=f"telegram-{td[:8]}")
        running_bots[token] = (task, bot)
        log.info("Bot ishga tushdi: id=%s template=%s digest=%s", bot_id, template, td[:10])
    except Exception:
        await bot.session.close()
        log.exception("Botni ishga tushirishda xato (bot_id=%s)", bot_id)


async def stop_bot(token: str) -> None:
    entry = running_bots.pop(token, None)
    if not entry:
        return
    task, bot = entry
    task.cancel()
    try:
        await asyncio.gather(task, return_exceptions=True)
    except Exception:
        pass
    try:
        await bot.session.close()
    except Exception:
        pass


async def stop_all_bots() -> None:
    tasks = []
    for task, _ in list(running_bots.values()):
        task.cancel()
        tasks.append(task)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    for _, bot in list(running_bots.values()):
        try:
            await bot.session.close()
        except Exception:
            pass
    running_bots.clear()


# ── Pydantic modellari ──

class RegisterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    username: str = Field(min_length=3, max_length=30, pattern=USERNAME_RE)
    password: str = Field(min_length=6, max_length=72)


class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    username: str = Field(min_length=1, max_length=30)
    password: str = Field(min_length=1, max_length=72)


class CreateBotRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    bot_token: str = Field(min_length=30, max_length=100)
    template: str = Field(min_length=3, max_length=20)


class ProductRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    price: int = Field(ge=0, le=1_000_000_000)
    description: str = Field(default="", max_length=500)


# ── Lifespan: faol botlarni qayta ishga tushiradi ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with db_lock:
        rows = db.execute("SELECT * FROM managed_bots WHERE is_active=1").fetchall()
        active = []
        for row in rows:
            if is_valid_trial(row):
                try:
                    active.append((decrypt_token(row["token_ciphertext"]), row["template"], row["id"]))
                except (InvalidToken, ValueError):
                    log.error("Token ochilmadi; bot_id=%s o'chirildi.", row["id"])
                    db.execute("UPDATE managed_bots SET is_active=0 WHERE id=?", (row["id"],))
            else:
                db.execute("UPDATE managed_bots SET is_active=0 WHERE id=?", (row["id"],))
        db.commit()
    for token, template, bot_id in active:
        await run_bot(token, template, bot_id)
    yield
    await stop_all_bots()
    db.close()


app = FastAPI(title="BotBuilder", version="2.0.0", lifespan=lifespan)


# ── Ommaviy endpointlar ──

@app.get("/", response_class=HTMLResponse)
async def home():
    return (BASE_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "service": "BotBuilder",
        "running_bots": sum(not task.done() for task, _ in running_bots.values()),
    }


@app.get("/api/stats")
async def public_stats():
    """Ommaviy statistika (token talab qilmaydi): jami va faol botlar."""
    async with db_lock:
        total = db.execute("SELECT COUNT(*) AS c FROM managed_bots").fetchone()["c"]
        active = db.execute("SELECT COUNT(*) AS c FROM managed_bots WHERE is_active=1").fetchone()["c"]
    return {"total_bots": total, "active_bots": active, "templates": len(VALID_TEMPLATES)}


# ── Autentifikatsiya ──

@app.post("/api/register")
async def api_register(req: RegisterRequest):
    try:
        result = await register_user(req.username, req.password)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    first = count_users() == 1
    return {
        "ok": True,
        "token": result["token"],
        "username": result["username"],
        "is_admin": result["is_admin"],
        "is_first": first,
    }


@app.post("/api/login")
async def api_login(req: LoginRequest):
    try:
        result = await login_user(req.username, req.password)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=401)
    return {
        "ok": True,
        "token": result["token"],
        "username": result["username"],
        "is_admin": result["is_admin"],
    }


@app.post("/api/logout")
async def api_logout(request: Request, user=Depends(get_current_user)):
    auth = request.headers.get("authorization", "")
    token = auth.replace("Bearer ", "", 1) if auth.lower().startswith("bearer ") else ""
    async with db_lock:
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit()
    return {"ok": True}


@app.get("/api/me")
async def api_me(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
        "created_at": user["created_at"],
    }


# ── Bot boshqaruvi ──

@app.post("/api/create-bot")
async def create_bot(req: CreateBotRequest, request: Request, user=Depends(get_current_user)):
    if req.template not in VALID_TEMPLATES:
        return JSONResponse({"ok": False, "error": "Bot shabloni noto'g'ri."}, status_code=400)
    ip = request.client.host if request.client else "unknown"
    if not allow_create(ip):
        return JSONResponse(
            {"ok": False, "error": "Juda ko'p urinish. Bir soatdan keyin qayta urinib ko'ring."},
            status_code=429,
        )

    token = req.bot_token.strip()
    test_bot = Bot(token=token)
    try:
        me = await test_bot.get_me()
        if not me.username:
            return JSONResponse({"ok": False, "error": "Bot username aniqlanmadi."}, status_code=400)
    except Exception:
        return JSONResponse(
            {"ok": False, "error": "Token noto'g'ri yoki Telegram bilan aloqa yo'q."},
            status_code=400,
        )
    finally:
        await test_bot.session.close()

    digest = token_digest(token)
    now = datetime.utcnow()
    trial_end = now + timedelta(days=3)
    async with db_lock:
        exists = db.execute("SELECT id FROM managed_bots WHERE token_hash=?", (digest,)).fetchone()
        if exists:
            return JSONResponse({"ok": False, "error": "Bu bot avval platformaga qo'shilgan."}, status_code=409)
        cur = db.execute(
            "INSERT INTO managed_bots (owner_id, username, token_ciphertext, token_hash, template, created_at, trial_ends_at, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (user["id"], me.username, encrypt_token(token), digest, req.template, now.isoformat(), trial_end.isoformat()),
        )
        bot_id = cur.lastrowid

        # Do'kon boti uchun standart mahsulotlarni yuklaymiz.
        if req.template == "shop":
            for name, price, desc in DEFAULT_PRODUCTS:
                db.execute(
                    "INSERT INTO shop_products (bot_id, name, price, description, created_at) VALUES (?, ?, ?, ?, ?)",
                    (bot_id, name, price, desc, now.isoformat()),
                )
        db.commit()

    await run_bot(token, req.template, bot_id)
    return {"ok": True, "bot_id": bot_id, "username": me.username, "trial_ends_at": trial_end.isoformat()}


def _bot_row_to_dict(row, include_owner: bool = False) -> dict:
    active = is_valid_trial(row)
    d = {
        "id": row["id"],
        "username": row["username"],
        "template": row["template"],
        "template_label": TEMPLATE_LABELS.get(row["template"], row["template"]),
        "created_at": row["created_at"],
        "trial_ends_at": datetime.fromisoformat(row["trial_ends_at"]).strftime("%Y-%m-%d"),
        "is_active": active,
    }
    if include_owner:
        d["owner"] = row["owner_username"] if "owner_username" in row.keys() else None
    return d


@app.get("/api/my-bots")
async def my_bots(user=Depends(get_current_user)):
    async with db_lock:
        rows = db.execute(
            "SELECT * FROM managed_bots WHERE owner_id=? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
    return [_bot_row_to_dict(r) for r in rows]


@app.get("/api/admin/bots")
async def admin_all_bots(user=Depends(require_admin)):
    async with db_lock:
        rows = db.execute(
            "SELECT b.*, u.username AS owner_username FROM managed_bots b "
            "LEFT JOIN users u ON b.owner_id = u.id ORDER BY b.id DESC",
        ).fetchall()
    return [_bot_row_to_dict(r, include_owner=True) for r in rows]


@app.delete("/api/bots/{bot_id}")
async def delete_bot(bot_id: int, user=Depends(get_current_user)):
    async with db_lock:
        row = db.execute("SELECT * FROM managed_bots WHERE id=?", (bot_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Bot topilmadi.")
        # Egasi yoki admin o'chira oladi.
        if row["owner_id"] != user["id"] and not user["is_admin"]:
            raise HTTPException(status_code=403, detail="Bu botni o'chirish huquqingiz yo'q.")
        token_ciphertext = row["token_ciphertext"]
        # Bog'liq ma'lumotlar foreign key CASCADE orqali o'chiriladi.
        db.execute("DELETE FROM managed_bots WHERE id=?", (bot_id,))
        db.commit()
    # Botni to'xtatamiz.
    try:
        token = decrypt_token(token_ciphertext)
    except (InvalidToken, ValueError):
        token = None
    if token:
        await stop_bot(token)
    return {"ok": True}


# ── Bot ma'lumotlari (faqat egasi/admin uchun) ──

async def _check_bot_owner(bot_id: int, user) -> dict:
    async with db_lock:
        row = db.execute("SELECT * FROM managed_bots WHERE id=?", (bot_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Bot topilmadi.")
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Bu bot ma'lumotlariga ruxsat yo'q.")
    return dict(row)


@app.get("/api/bots/{bot_id}/products")
async def bot_products(bot_id: int, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        rows = db.execute(
            "SELECT id, name, price, description FROM shop_products WHERE bot_id=? ORDER BY id",
            (bot_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/bots/{bot_id}/products")
async def add_product(bot_id: int, req: ProductRequest, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        cur = db.execute(
            "INSERT INTO shop_products (bot_id, name, price, description, created_at) VALUES (?, ?, ?, ?, ?)",
            (bot_id, req.name, req.price, req.description, datetime.utcnow().isoformat()),
        )
        db.commit()
        pid = cur.lastrowid
    return {"ok": True, "id": pid}


@app.delete("/api/bots/{bot_id}/products/{pid}")
async def delete_product(bot_id: int, pid: int, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        db.execute("DELETE FROM shop_products WHERE id=? AND bot_id=?", (pid, bot_id))
        db.commit()
    return {"ok": True}


@app.get("/api/bots/{bot_id}/orders")
async def bot_orders(bot_id: int, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        rows = db.execute(
            "SELECT id, tg_username, customer_name, customer_phone, items_json, total, status, created_at "
            "FROM shop_orders WHERE bot_id=? ORDER BY id DESC LIMIT 100",
            (bot_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["items"] = json.loads(d.pop("items_json"))
        except Exception:
            d["items"] = []
        out.append(d)
    return out


@app.get("/api/bots/{bot_id}/tickets")
async def bot_tickets(bot_id: int, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        rows = db.execute(
            "SELECT id, tg_username, ticket_no, message, status, created_at "
            "FROM support_tickets WHERE bot_id=? ORDER BY id DESC LIMIT 100",
            (bot_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/bots/{bot_id}/results")
async def bot_results(bot_id: int, user=Depends(get_current_user)):
    await _check_bot_owner(bot_id, user)
    async with db_lock:
        rows = db.execute(
            "SELECT id, tg_username, score, total, created_at FROM quiz_results "
            "WHERE bot_id=? ORDER BY id DESC LIMIT 100",
            (bot_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/bots/{bot_id}/toggle")
async def toggle_bot(bot_id: int, user=Depends(get_current_user)):
    """Admin botni vaqtincha to'xtatadi yoki qayta ishga tushiradi."""
    async with db_lock:
        row = db.execute("SELECT * FROM managed_bots WHERE id=?", (bot_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Bot topilmadi.")
        if row["owner_id"] != user["id"] and not user["is_admin"]:
            raise HTTPException(status_code=403, detail="Huquq yo'q.")
        new_active = 0 if row["is_active"] else 1
        db.execute("UPDATE managed_bots SET is_active=? WHERE id=?", (new_active, bot_id))
        db.commit()
    if new_active == 0:
        try:
            token = decrypt_token(row["token_ciphertext"])
            await stop_bot(token)
        except (InvalidToken, ValueError):
            pass
    else:
        try:
            token = decrypt_token(row["token_ciphertext"])
            await run_bot(token, row["template"], row["id"])
        except (InvalidToken, ValueError):
            pass
    return {"ok": True, "is_active": bool(new_active)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
