"""SQLite ma'lumotlar bazasi: ulanish, jadvallar va yordamchi funksiyalar."""
import asyncio
import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "botbuilder.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Bitta global ulanish — aiogram polling va FastAPI bilan birga ishlaydi.
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA foreign_keys = ON")
db_lock = asyncio.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS managed_bots (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username          TEXT NOT NULL,
    token_ciphertext  TEXT NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    template          TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    trial_ends_at     TEXT NOT NULL,
    is_active         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS shop_products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id      INTEGER NOT NULL REFERENCES managed_bots(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    price       INTEGER NOT NULL,
    description TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shop_cart (
    bot_id      INTEGER NOT NULL REFERENCES managed_bots(id) ON DELETE CASCADE,
    tg_user_id  INTEGER NOT NULL,
    product_id  INTEGER NOT NULL REFERENCES shop_products(id) ON DELETE CASCADE,
    qty         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (bot_id, tg_user_id, product_id)
);

CREATE TABLE IF NOT EXISTS shop_orders (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id         INTEGER NOT NULL REFERENCES managed_bots(id) ON DELETE CASCADE,
    tg_user_id     INTEGER NOT NULL,
    tg_username    TEXT,
    customer_name  TEXT,
    customer_phone TEXT,
    items_json     TEXT NOT NULL,
    total          INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'new',
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id      INTEGER NOT NULL REFERENCES managed_bots(id) ON DELETE CASCADE,
    tg_user_id  INTEGER NOT NULL,
    tg_username TEXT,
    ticket_no   INTEGER NOT NULL,
    message     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quiz_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id      INTEGER NOT NULL REFERENCES managed_bots(id) ON DELETE CASCADE,
    tg_user_id  INTEGER NOT NULL,
    tg_username TEXT,
    score       INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);
"""


def init_db() -> None:
    """Barcha jadvallarni yaratadi va eski DB uchun migratsiyani bajaradi."""
    db.executescript(SCHEMA)

    # Eski managed_bots jadvali uchun owner_id ustunini qo'shamiz (agar yo'q bo'lsa).
    cols = {row["name"] for row in db.execute("PRAGMA table_info(managed_bots)")}
    if "owner_id" not in cols:
        db.execute(
            "ALTER TABLE managed_bots ADD COLUMN owner_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id)"
        )

    db.commit()


def count_users() -> int:
    return db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
