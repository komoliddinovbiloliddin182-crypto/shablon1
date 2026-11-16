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
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from aiogram import Bot
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from auth import (
    ADMIN_USERNAME,
    USERNAME_RE,
    create_session,
    ensure_admin_account,
    get_current_user,
    login_user,
    register_user,
    require_admin,
)
from bot_engine import DEFAULT_PRODUCTS, build_dispatcher
from db import count_users, db, db_lock, get_setting, get_site_admin_id, init_db, set_setting

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

# ── Yuklashlar jildi (to'lov cheklari rasmlari) ──
# Render diskdagi doimiy joyga yo'naltiriladi (UPLOADS_DIR=/var/data/uploads).
UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", str(BASE_DIR / "uploads")))
CHECKS_DIR = UPLOADS_DIR / "checks"
CHECKS_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_CHECK_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".heic"}
MAX_CHECK_BYTES = 10 * 1024 * 1024  # 10 MB

init_db()

# Sozlama kalitlari va standart qiymatlari.
SETTING_DEFAULTS = {
    "bot_price": "50000",        # 2-bot va undan keyingi botlar narxi (so'm)
    "bot_trial_days": "3",       # 1-bot bepul sinov muddati (kun)
    "paid_bot_days": "30",       # Pullik bot amal qilish muddati (kun)
}


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
    # Doimiy sayt adminini kafolatlaymiz (admin / BILOLIDDIN).
    await ensure_admin_account()
    # Standart sozlamalarni kafolatlaymiz (faqat yo'q bo'lsa).
    async with db_lock:
        for k, v in SETTING_DEFAULTS.items():
            if db.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone() is None:
                db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))
        db.commit()
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
    return {
        "ok": True,
        "token": result["token"],
        "username": result["username"],
        "is_admin": result["is_admin"],
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
        "balance": user["balance"],
        "ever_created_bot": bool(user["ever_created_bot"]),
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

    # ── Narx logikasi ──
    # Admin har doim bepul. Oddiy foydalanuvchining 1-boti bepul (sinov).
    # Qolgan botlar admin belgilagan narxga, balansdan yechiladi.
    is_admin = bool(user["is_admin"])
    is_first_bot = not bool(user["ever_created_bot"])
    bot_price = int(get_setting("bot_price", SETTING_DEFAULTS["bot_price"]))
    trial_days = int(get_setting("bot_trial_days", SETTING_DEFAULTS["bot_trial_days"]))
    paid_days = int(get_setting("paid_bot_days", SETTING_DEFAULTS["paid_bot_days"]))

    if is_admin or is_first_bot:
        charge = 0
        valid_days = trial_days if is_first_bot else trial_days
        is_paid = 0
        pricing_note = "Bepul sinov" if (is_first_bot and not is_admin) else "Admin hisobi (bepul)"
    else:
        # Balansni tekshiramiz (db_lock ichida qayta o'qymiz — poyga holatidan saqlanish).
        charge = bot_price
        valid_days = paid_days
        is_paid = 1
        pricing_note = f"To'langan ({bot_price} so'm)"

    digest = token_digest(token)
    now = datetime.utcnow()
    trial_end = now + timedelta(days=valid_days)

    async with db_lock:
        exists = db.execute("SELECT id FROM managed_bots WHERE token_hash=?", (digest,)).fetchone()
        if exists:
            return JSONResponse({"ok": False, "error": "Bu bot avval platformaga qo'shilgan."}, status_code=409)

        if not is_admin and not is_first_bot:
            current_balance = db.execute(
                "SELECT balance FROM users WHERE id=?", (user["id"],)
            ).fetchone()["balance"]
            if current_balance < charge:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": (
                            f"Balansda mablag' yetarli emas. Bot narxi {charge} so'm, "
                            f"sizning balansingiz {current_balance} so'm. "
                            "Iltimos, hisobni to'ldiring (admin chekni tasdiqlagandan keyin)."
                        ),
                    },
                    status_code=402,
                )

        cur = db.execute(
            "INSERT INTO managed_bots (owner_id, username, token_ciphertext, token_hash, template, created_at, trial_ends_at, is_active, is_paid) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (user["id"], me.username, encrypt_token(token), digest, req.template, now.isoformat(), trial_end.isoformat(), is_paid),
        )
        bot_id = cur.lastrowid

        # Pullik bot uchun balansdan yechamiz va ledgerga yozamiz (bot_id bilan bog'lab).
        if charge > 0:
            db.execute("UPDATE users SET balance=balance-? WHERE id=?", (charge, user["id"]))
            db.execute(
                "INSERT INTO balance_ledger (user_id, delta, reason, ref_id, created_at) "
                "VALUES (?, ?, 'bot_purchase', ?, ?)",
                (user["id"], -charge, bot_id, now.isoformat()),
            )

        # Do'kon boti uchun standart mahsulotlarni yuklaymiz.
        if req.template == "shop":
            for name, price, desc in DEFAULT_PRODUCTS:
                db.execute(
                    "INSERT INTO shop_products (bot_id, name, price, description, created_at) VALUES (?, ?, ?, ?, ?)",
                    (bot_id, name, price, desc, now.isoformat()),
                )

        # 1-bot yaratilgach, ever_created_bot bayrog'ini o'rnatamiz (admin uchun o'zgarmaydi).
        if not is_admin and is_first_bot:
            db.execute("UPDATE users SET ever_created_bot=1 WHERE id=?", (user["id"],))

        db.commit()

    await run_bot(token, req.template, bot_id)
    new_balance = None
    if charge > 0:
        async with db_lock:
            new_balance = db.execute("SELECT balance FROM users WHERE id=?", (user["id"],)).fetchone()["balance"]
    return {
        "ok": True,
        "bot_id": bot_id,
        "username": me.username,
        "trial_ends_at": trial_end.isoformat(),
        "is_paid": bool(is_paid),
        "charged": charge,
        "pricing_note": pricing_note,
        "valid_days": valid_days,
        "balance_after": new_balance,
    }


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
        "is_paid": bool(row["is_paid"]) if "is_paid" in row.keys() else False,
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


# ── Admin: kengaytirilgan boshqaruv paneli ──

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(require_admin)):
    """Butun platforma bo'yicha to'liq statistika."""
    async with db_lock:
        users_total = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        users_admins = db.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin=1").fetchone()["c"]
        users_blocked = db.execute("SELECT COUNT(*) AS c FROM users WHERE is_blocked=1").fetchone()["c"]
        bots_total = db.execute("SELECT COUNT(*) AS c FROM managed_bots").fetchone()["c"]
        bots_active = db.execute("SELECT COUNT(*) AS c FROM managed_bots WHERE is_active=1").fetchone()["c"]
        tpl_rows = db.execute(
            "SELECT template, COUNT(*) AS c FROM managed_bots GROUP BY template"
        ).fetchall()
        orders_total = db.execute("SELECT COUNT(*) AS c FROM shop_orders").fetchone()["c"]
        revenue = db.execute("SELECT COALESCE(SUM(total), 0) AS s FROM shop_orders").fetchone()["s"]
        tickets_total = db.execute("SELECT COUNT(*) AS c FROM support_tickets").fetchone()["c"]
        tickets_open = db.execute("SELECT COUNT(*) AS c FROM support_tickets WHERE status='open'").fetchone()["c"]
        results_total = db.execute("SELECT COUNT(*) AS c FROM quiz_results").fetchone()["c"]
        avg_score_row = db.execute(
            "SELECT COALESCE(ROUND(AVG(CAST(score AS REAL) / total) * 100, 1), 0) AS a FROM quiz_results"
        ).fetchone()
        # Moliyaviy statistika.
        total_balance = db.execute("SELECT COALESCE(SUM(balance), 0) AS s FROM users").fetchone()["s"]
        pending_topups = db.execute(
            "SELECT COUNT(*) AS c, COALESCE(SUM(amount), 0) AS s FROM balance_topups WHERE status='pending'"
        ).fetchone()
        approved_total = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS s FROM balance_topups WHERE status='approved'"
        ).fetchone()["s"]
        spent_total = db.execute(
            "SELECT COALESCE(SUM(-delta), 0) AS s FROM balance_ledger WHERE reason='bot_purchase'"
        ).fetchone()["s"]
    by_template = {t["template"]: t["c"] for t in tpl_rows}
    return {
        "users": {"total": users_total, "admins": users_admins, "blocked": users_blocked},
        "bots": {
            "total": bots_total,
            "active": bots_active,
            "by_template": {t: by_template.get(t, 0) for t in VALID_TEMPLATES},
        },
        "orders": {"total": orders_total, "revenue": revenue},
        "tickets": {"total": tickets_total, "open": tickets_open},
        "quiz": {"total": results_total, "avg_score_pct": avg_score_row["a"]},
        "finance": {
            "total_balance": total_balance,
            "pending_topups_count": pending_topups["c"],
            "pending_topups_amount": pending_topups["s"],
            "approved_total": approved_total,
            "spent_total": spent_total,
        },
        "running_bots": sum(not task.done() for task, _ in running_bots.values()),
    }


@app.get("/api/admin/users")
async def admin_users(user=Depends(require_admin)):
    """Barcha foydalanuvchilar (balans va botlar soni bilan)."""
    async with db_lock:
        rows = db.execute(
            "SELECT u.id, u.username, u.is_admin, u.is_blocked, u.balance, u.ever_created_bot, u.created_at, "
            "COUNT(b.id) AS bots_count, "
            "(SELECT COUNT(*) FROM balance_topups t WHERE t.user_id=u.id AND t.status='pending') AS pending_topups "
            "FROM users u LEFT JOIN managed_bots b ON b.owner_id = u.id "
            "GROUP BY u.id ORDER BY u.is_admin DESC, u.id DESC",
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "username": r["username"],
            "is_admin": bool(r["is_admin"]),
            "is_blocked": bool(r["is_blocked"]),
            "is_site_admin": r["username"] == ADMIN_USERNAME,
            "balance": r["balance"],
            "ever_created_bot": bool(r["ever_created_bot"]),
            "bots_count": r["bots_count"],
            "pending_topups": r["pending_topups"],
            "created_at": datetime.fromisoformat(r["created_at"]).strftime("%Y-%m-%d %H:%M"),
        })
    return out


@app.post("/api/admin/users/{uid}/block")
async def admin_toggle_block(uid: int, user=Depends(require_admin)):
    """Foydalanuvchini bloklaydi/yechadi. Sayt admini va o'zini bloklab bo'lmaydi."""
    if uid == user["id"]:
        raise HTTPException(status_code=400, detail="O'zingizni bloklab bo'lmaydi.")
    async with db_lock:
        row = db.execute("SELECT username, is_blocked FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi.")
        if row["username"] == ADMIN_USERNAME:
            raise HTTPException(status_code=400, detail="Sayt adminini bloklab bo'lmaydi.")
        new_val = 0 if row["is_blocked"] else 1
        db.execute("UPDATE users SET is_blocked=? WHERE id=?", (new_val, uid))
        if new_val == 1:
            # Bloklangan foydalanuvchining barcha sessiyalarini o'chiramiz.
            db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        db.commit()
    return {"ok": True, "is_blocked": bool(new_val)}


@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: int, user=Depends(require_admin)):
    """Foydalanuvchini o'chiradi (unventing botlari va ma'lumotlari bilan). Sayt admini
    va o'zini o'chirib bo'lmaydi."""
    if uid == user["id"]:
        raise HTTPException(status_code=400, detail="O'zingizni o'chirib bo'lmaydi.")
    async with db_lock:
        row = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi.")
        if row["username"] == ADMIN_USERNAME:
            raise HTTPException(status_code=400, detail="Sayt adminini o'chirib bo'lmaydi.")
        # Bog'liq ma'lumotlar foreign key CASCADE orqali o'chiriladi (botlar, sessiyalar).
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
    return {"ok": True}


@app.get("/api/admin/orders")
async def admin_all_orders(user=Depends(require_admin)):
    """Barcha do'kon botlarining buyurtmalari."""
    async with db_lock:
        rows = db.execute(
            "SELECT o.id, o.bot_id, b.username AS bot_username, b.template, "
            "o.tg_username, o.customer_name, o.customer_phone, o.items_json, o.total, o.status, o.created_at "
            "FROM shop_orders o JOIN managed_bots b ON o.bot_id = b.id "
            "ORDER BY o.id DESC LIMIT 200",
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


@app.get("/api/admin/tickets")
async def admin_all_tickets(user=Depends(require_admin)):
    """Barcha yordam botlarining ticketlari."""
    async with db_lock:
        rows = db.execute(
            "SELECT t.id, t.bot_id, b.username AS bot_username, t.tg_username, "
            "t.ticket_no, t.message, t.status, t.created_at "
            "FROM support_tickets t JOIN managed_bots b ON t.bot_id = b.id "
            "ORDER BY t.id DESC LIMIT 200",
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/admin/results")
async def admin_all_results(user=Depends(require_admin)):
    """Barcha quiz botlarining natijalari."""
    async with db_lock:
        rows = db.execute(
            "SELECT r.id, r.bot_id, b.username AS bot_username, r.tg_username, "
            "r.score, r.total, r.created_at "
            "FROM quiz_results r JOIN managed_bots b ON r.bot_id = b.id "
            "ORDER BY r.id DESC LIMIT 200",
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/tickets/{tid}/status")
async def admin_ticket_status(tid: int, user=Depends(require_admin)):
    """Admin ticket holatini almashtiradi (open ↔ closed)."""
    async with db_lock:
        row = db.execute("SELECT status FROM support_tickets WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Ticket topilmadi.")
        new_status = "closed" if row["status"] == "open" else "open"
        db.execute("UPDATE support_tickets SET status=? WHERE id=?", (new_status, tid))
        db.commit()
    return {"ok": True, "status": new_status}


@app.post("/api/admin/orders/{oid}/status")
async def admin_order_status(oid: int, status_value: str = "done", user=Depends(require_admin)):
    """Admin buyurtma holatini yangilaydi."""
    async with db_lock:
        row = db.execute("SELECT id FROM shop_orders WHERE id=?", (oid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Buyurtma topilmadi.")
        db.execute("UPDATE shop_orders SET status=? WHERE id=?", (status_value, oid))
        db.commit()
    return {"ok": True, "status": status_value}


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


# ── Balans: mijoz to'lov cheki so'rovi ──

class TopupNoteRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    admin_note: str = Field(default="", max_length=500)


@app.post("/api/topup/request")
async def topup_request(
    amount: int = Form(...),
    check: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """Mijoz balansni to'ldirish uchun summa va to'lov cheki rasmini yuklaydi.

    Admin chekni ko'rib chiqadi va tasdiqlasa — summa balansga tushadi,
    rad etsa — hech narsa o'zgarmaydi.
    """
    if amount < 1000 or amount > 100_000_000:
        return JSONResponse(
            {"ok": False, "error": "Summa 1 000 dan 100 000 000 so'mgacha bo'lishi kerak."},
            status_code=400,
        )
    ext = Path(check.filename or "").suffix.lower()
    if ext not in ALLOWED_CHECK_EXT:
        return JSONResponse(
            {"ok": False, "error": "Rasm formati qo'llab-quvvatlanmaydi. JPG, PNG yoki WEBP ishlating."},
            status_code=400,
        )
    content = await check.read()
    if not content:
        return JSONResponse({"ok": False, "error": "Rasm bo'sh."}, status_code=400)
    if len(content) > MAX_CHECK_BYTES:
        return JSONResponse(
            {"ok": False, "error": "Rasm hajmi 10 MB dan oshmasligi kerak."}, status_code=400
        )
    fname = f"{user['id']}_{int(time.time())}_{secrets.token_hex(6)}{ext}"
    path = CHECKS_DIR / fname
    path.write_bytes(content)
    now = datetime.utcnow().isoformat()
    async with db_lock:
        cur = db.execute(
            "INSERT INTO balance_topups (user_id, amount, check_path, status, created_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (user["id"], amount, str(path), now),
        )
        db.commit()
        tid = cur.lastrowid
    return {"ok": True, "topup_id": tid, "amount": amount, "status": "pending"}


@app.get("/api/topup/my")
async def my_topups(user=Depends(get_current_user)):
    """Mijozning o'z to'lov so'rovlari tarixi."""
    async with db_lock:
        rows = db.execute(
            "SELECT id, amount, status, admin_note, created_at, reviewed_at "
            "FROM balance_topups WHERE user_id=? ORDER BY id DESC LIMIT 100",
            (user["id"],),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        d["reviewed_at"] = (d["reviewed_at"] or "")[:16].replace("T", " ") or None
        out.append(d)
    return out


@app.get("/api/balance/ledger")
async def my_ledger(user=Depends(get_current_user)):
    """Mijozning balans harakatlari tarixi (+to'lov, -bot xaridi)."""
    async with db_lock:
        rows = db.execute(
            "SELECT id, delta, reason, ref_id, created_at FROM balance_ledger "
            "WHERE user_id=? ORDER BY id DESC LIMIT 100",
            (user["id"],),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        out.append(d)
    return out


# ── Admin: to'lov cheklarini ko'rib chiqish ──

@app.get("/api/admin/topups")
async def admin_topups(status_filter: str = "all", user=Depends(require_admin)):
    """Barcha to'lov so'rovlari (status bo'yicha filtrlash mumkin)."""
    valid = {"pending", "approved", "rejected", "all"}
    if status_filter not in valid:
        status_filter = "all"
    async with db_lock:
        if status_filter == "all":
            rows = db.execute(
                "SELECT t.id, t.user_id, u.username, t.amount, t.status, t.admin_note, "
                "t.created_at, t.reviewed_at "
                "FROM balance_topups t JOIN users u ON t.user_id=u.id "
                "ORDER BY CASE t.status WHEN 'pending' THEN 0 ELSE 1 END, t.id DESC LIMIT 300",
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT t.id, t.user_id, u.username, t.amount, t.status, t.admin_note, "
                "t.created_at, t.reviewed_at "
                "FROM balance_topups t JOIN users u ON t.user_id=u.id "
                "WHERE t.status=? ORDER BY t.id DESC LIMIT 300",
                (status_filter,),
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        d["reviewed_at"] = (d["reviewed_at"] or "")[:16].replace("T", " ") or None
        out.append(d)
    return out


@app.get("/api/admin/topups/{tid}/check")
async def admin_topup_check_image(tid: int, user=Depends(require_admin)):
    """To'lov cheki rasmini faqat admin ko'radi."""
    async with db_lock:
        row = db.execute("SELECT check_path FROM balance_topups WHERE id=?", (tid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="So'rov topilmadi.")
    path = Path(row["check_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Chek rasmi topilmadi.")
    return FileResponse(str(path))


@app.post("/api/admin/topups/{tid}/approve")
async def admin_approve_topup(tid: int, req: TopupNoteRequest, user=Depends(require_admin)):
    """Admin so'rovni tasdiqlaydi — summa mijoz balansiga tushadi."""
    now = datetime.utcnow().isoformat()
    async with db_lock:
        row = db.execute("SELECT * FROM balance_topups WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="So'rov topilmadi.")
        if row["status"] != "pending":
            raise HTTPException(status_code=400, detail="Bu so'rov allaqachon ko'rib chiqilgan.")
        # Balansga qo'shamiz.
        db.execute("UPDATE users SET balance=balance+? WHERE id=?", (row["amount"], row["user_id"]))
        # Ledger.
        db.execute(
            "INSERT INTO balance_ledger (user_id, delta, reason, ref_id, created_at) "
            "VALUES (?, ?, 'topup', ?, ?)",
            (row["user_id"], row["amount"], row["id"], now),
        )
        db.execute(
            "UPDATE balance_topups SET status='approved', admin_note=?, reviewed_by=?, reviewed_at=? WHERE id=?",
            (req.admin_note, user["id"], now, tid),
        )
        new_balance = db.execute(
            "SELECT balance FROM users WHERE id=?", (row["user_id"],)
        ).fetchone()["balance"]
        db.commit()
    return {"ok": True, "status": "approved", "new_balance": new_balance}


@app.post("/api/admin/topups/{tid}/reject")
async def admin_reject_topup(tid: int, req: TopupNoteRequest, user=Depends(require_admin)):
    """Admin so'rovni rad etadi — balans o'zgarmaydi."""
    now = datetime.utcnow().isoformat()
    async with db_lock:
        row = db.execute("SELECT * FROM balance_topups WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="So'rov topilmadi.")
        if row["status"] != "pending":
            raise HTTPException(status_code=400, detail="Bu so'rov allaqachon ko'rib chiqilgan.")
        db.execute(
            "UPDATE balance_topups SET status='rejected', admin_note=?, reviewed_by=?, reviewed_at=? WHERE id=?",
            (req.admin_note, user["id"], now, tid),
        )
        db.commit()
    return {"ok": True, "status": "rejected"}


# ── Admin: narx va sozlamalar ──

class SettingsUpdate(BaseModel):
    bot_price: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    bot_trial_days: Optional[int] = Field(default=None, ge=0, le=365)
    paid_bot_days: Optional[int] = Field(default=None, ge=1, le=3650)


@app.get("/api/admin/settings")
async def admin_get_settings(user=Depends(require_admin)):
    """Joriy narx va muddat sozlamalari."""
    return {
        "bot_price": int(get_setting("bot_price", SETTING_DEFAULTS["bot_price"])),
        "bot_trial_days": int(get_setting("bot_trial_days", SETTING_DEFAULTS["bot_trial_days"])),
        "paid_bot_days": int(get_setting("paid_bot_days", SETTING_DEFAULTS["paid_bot_days"])),
    }


@app.post("/api/admin/settings")
async def admin_update_settings(req: SettingsUpdate, user=Depends(require_admin)):
    """Admin bot narxini va muddatlarni o'zgartiradi."""
    async with db_lock:
        if req.bot_price is not None:
            set_setting("bot_price", str(req.bot_price))
        if req.bot_trial_days is not None:
            set_setting("bot_trial_days", str(req.bot_trial_days))
        if req.paid_bot_days is not None:
            set_setting("paid_bot_days", str(req.paid_bot_days))
        db.commit()
    return {
        "ok": True,
        "bot_price": int(get_setting("bot_price", SETTING_DEFAULTS["bot_price"])),
        "bot_trial_days": int(get_setting("bot_trial_days", SETTING_DEFAULTS["bot_trial_days"])),
        "paid_bot_days": int(get_setting("paid_bot_days", SETTING_DEFAULTS["paid_bot_days"])),
    }


# Ommaviy narx (admin panelga kirish uchun, token talab qilmaydi).
@app.get("/api/pricing")
async def public_pricing():
    return {
        "bot_price": int(get_setting("bot_price", SETTING_DEFAULTS["bot_price"])),
        "bot_trial_days": int(get_setting("bot_trial_days", SETTING_DEFAULTS["bot_trial_days"])),
        "paid_bot_days": int(get_setting("paid_bot_days", SETTING_DEFAULTS["paid_bot_days"])),
        "first_bot_free": True,
    }


# ── Admin: ommaviy xabar (broadcast) ──

class BroadcastRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    body: str = Field(min_length=1, max_length=2000)


@app.post("/api/admin/broadcast")
async def admin_send_broadcast(req: BroadcastRequest, user=Depends(require_admin)):
    """Admin barcha foydalanuvchilarga xabar yuboradi."""
    now = datetime.utcnow().isoformat()
    async with db_lock:
        cur = db.execute(
            "INSERT INTO admin_broadcasts (admin_id, body, created_at) VALUES (?, ?, ?)",
            (user["id"], req.body, now),
        )
        recipients = db.execute(
            "SELECT COUNT(*) AS c FROM users WHERE is_blocked=0"
        ).fetchone()["c"]
        db.commit()
        bid = cur.lastrowid
    return {"ok": True, "broadcast_id": bid, "recipients": recipients}


@app.get("/api/admin/broadcasts")
async def admin_list_broadcasts(user=Depends(require_admin)):
    """Yuborilgan ommaviy xabarlar tarixi."""
    async with db_lock:
        rows = db.execute(
            "SELECT b.id, b.body, b.created_at, u.username AS admin_username "
            "FROM admin_broadcasts b JOIN users u ON b.admin_id=u.id "
            "ORDER BY b.id DESC LIMIT 100",
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        out.append(d)
    return out


# ── Admin ↔ foydalanuvchi suhbati ──

class ChatMessage(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    body: str = Field(min_length=1, max_length=2000)


@app.get("/api/inbox")
async def my_inbox(user=Depends(get_current_user)):
    """Mijoz inbox'i: ommaviy xabarlar + admin bilan suhbatning oxirgi xabari."""
    admin_id = get_site_admin_id()
    async with db_lock:
        broadcasts = db.execute(
            "SELECT id, body, created_at FROM admin_broadcasts ORDER BY id DESC LIMIT 50",
        ).fetchall()
        unread = db.execute(
            "SELECT COUNT(*) AS c FROM admin_chats WHERE to_user_id=? AND from_user_id=? AND is_read=0",
            (user["id"], admin_id),
        ).fetchone()["c"]
        last_admin_msg = db.execute(
            "SELECT body, created_at FROM admin_chats WHERE from_user_id=? AND to_user_id=? "
            "ORDER BY id DESC LIMIT 1",
            (admin_id, user["id"]),
        ).fetchone()
    return {
        "broadcasts": [
            {"id": b["id"], "body": b["body"], "created_at": b["created_at"][:16].replace("T", " ")}
            for b in broadcasts
        ],
        "unread_admin_messages": unread,
        "last_admin_message": (
            {"body": last_admin_msg["body"], "created_at": last_admin_msg["created_at"][:16].replace("T", " ")}
            if last_admin_msg
            else None
        ),
    }


@app.get("/api/chat/admin/messages")
async def my_chat_with_admin(user=Depends(get_current_user)):
    """Mijoz va admin o'rtasidagi to'liq suhbat."""
    admin_id = get_site_admin_id()
    async with db_lock:
        rows = db.execute(
            "SELECT id, from_user_id, to_user_id, body, is_read, created_at FROM admin_chats "
            "WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) "
            "ORDER BY id ASC LIMIT 500",
            (user["id"], admin_id, admin_id, user["id"]),
        ).fetchall()
        # Foydalanuvchiga kelgan (admin→user) xabarlarni o'qilgan deb belgilaymiz.
        db.execute(
            "UPDATE admin_chats SET is_read=1 WHERE to_user_id=? AND from_user_id=?",
            (user["id"], admin_id),
        )
        db.commit()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        d["is_mine"] = d["from_user_id"] == user["id"]
        out.append(d)
    return out


@app.post("/api/chat/admin")
async def user_send_to_admin(req: ChatMessage, user=Depends(get_current_user)):
    """Mijoz adminga xabar yuboradi."""
    admin_id = get_site_admin_id()
    now = datetime.utcnow().isoformat()
    async with db_lock:
        cur = db.execute(
            "INSERT INTO admin_chats (from_user_id, to_user_id, body, is_read, created_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (user["id"], admin_id, req.body, now),
        )
        db.commit()
        mid = cur.lastrowid
    return {"ok": True, "id": mid}


@app.get("/api/admin/chats")
async def admin_chat_threads(user=Depends(require_admin)):
    """Admin bilan suhbatlashgan foydalanuvchilar ro'yxati (oxirgi xabar bilan)."""
    admin_id = user["id"]
    async with db_lock:
        rows = db.execute(
            "SELECT u.id, u.username, u.is_blocked, "
            "(SELECT c.body FROM admin_chats c WHERE (c.from_user_id=u.id AND c.to_user_id=?) "
            " OR (c.from_user_id=? AND c.to_user_id=u.id) ORDER BY c.id DESC LIMIT 1) AS last_body, "
            "(SELECT c.created_at FROM admin_chats c WHERE (c.from_user_id=u.id AND c.to_user_id=?) "
            " OR (c.from_user_id=? AND c.to_user_id=u.id) ORDER BY c.id DESC LIMIT 1) AS last_at, "
            "(SELECT COUNT(*) FROM admin_chats c WHERE c.from_user_id=u.id AND c.to_user_id=? AND c.is_read=0) AS unread "
            "FROM users u "
            "WHERE u.id != ? AND EXISTS (SELECT 1 FROM admin_chats c WHERE "
            "(c.from_user_id=u.id AND c.to_user_id=?) OR (c.from_user_id=? AND c.to_user_id=u.id)) "
            "ORDER BY last_at DESC",
            (admin_id, admin_id, admin_id, admin_id, admin_id, admin_id, admin_id, admin_id),
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "username": r["username"],
            "is_blocked": bool(r["is_blocked"]),
            "last_body": r["last_body"],
            "last_at": r["last_at"][:16].replace("T", " ") if r["last_at"] else None,
            "unread": r["unread"],
        })
    return out


@app.get("/api/admin/chats/{uid}")
async def admin_chat_thread(uid: int, user=Depends(require_admin)):
    """Admin va konkret foydalanuvchi o'rtasidagi suhbat."""
    admin_id = user["id"]
    async with db_lock:
        u = db.execute("SELECT id, username FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi.")
        rows = db.execute(
            "SELECT id, from_user_id, to_user_id, body, is_read, created_at FROM admin_chats "
            "WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) "
            "ORDER BY id ASC LIMIT 500",
            (uid, admin_id, admin_id, uid),
        ).fetchall()
        # Mijozdan kelgan (user→admin) xabarlarni o'qilgan deb belgilaymiz.
        db.execute(
            "UPDATE admin_chats SET is_read=1 WHERE from_user_id=? AND to_user_id=?",
            (uid, admin_id),
        )
        db.commit()
    out = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"][:16].replace("T", " ")
        d["is_mine"] = d["from_user_id"] == admin_id
        out.append(d)
    return {"user": {"id": u["id"], "username": u["username"]}, "messages": out}


@app.post("/api/admin/chats/{uid}")
async def admin_reply_chat(uid: int, req: ChatMessage, user=Depends(require_admin)):
    """Admin foydalanuvchiga xabar yuboradi."""
    admin_id = user["id"]
    if uid == admin_id:
        raise HTTPException(status_code=400, detail="O'zingizga xabar yubora olmaysiz.")
    now = datetime.utcnow().isoformat()
    async with db_lock:
        u = db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi.")
        cur = db.execute(
            "INSERT INTO admin_chats (from_user_id, to_user_id, body, is_read, created_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (admin_id, uid, req.body, now),
        )
        db.commit()
        mid = cur.lastrowid
    return {"ok": True, "id": mid}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
