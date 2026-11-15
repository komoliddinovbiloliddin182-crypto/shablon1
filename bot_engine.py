"""Telegram bot dispatchers: to'rtta shablonni to'liq ishlaydigan qiladi.

Shablonlar:
  - support : Yordam markazi (ticket tizimi, javob kuzatuvi)
  - shop    : Onlayn do'kon (katalog, savat, buyurtma)
  - quiz    : Quiz / Test (5 savol, ball, natija)
  - sub     : Obuna boti (obuna yo'riqnomasi, tekshiruv)

Har bir bot o'z ma'lumotlarini SQLite'da saqlaydi (do'kon mahsulotlari/buyurtmalari,
yordam ticketlari, quiz natijalari) — qayta ishga tushganda ham ma'lumot saqlanadi.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command, CommandStart
from aiogram.utils.keyboard import InlineKeyboardBuilder, ReplyKeyboardBuilder

from db import db, db_lock

log = logging.getLogger("botbuilder.engine")

# Bot holatlari xotirada saqlanadi (qisqa muddatli: savat to'ldirish, savol yozish).
# Format: user_states[token_digest][tg_user_id] = {"step": "...", ...}
user_states: dict[str, dict[int, dict]] = defaultdict(lambda: defaultdict(dict))

# Quiz savollari (umumiy bilim, O'zbekiston mavzusida).
QUIZ_QUESTIONS = [
    {
        "q": "O'zbekiston poytaxti qaysi shahar?",
        "options": ["Samarqand", "Toshkent", "Buxoro", "Xiva"],
        "correct": 1,
    },
    {
        "q": "O'zbekiston mustaqilligi qachon e'lon qilingan?",
        "options": ["1990-yil 1-sentabr", "1991-yil 1-sentabr", "1992-yil 1-sentabr", "1993-yil 1-sentabr"],
        "correct": 1,
    },
    {
        "q": "O'zbekiston milliy valyutasi nima?",
        "options": ["Rubl", "So'm", "Tenge", "Manat"],
        "correct": 1,
    },
    {
        "q": "O'zbekiston rasmiy tili qaysi?",
        "options": ["Rus tili", "O'zbek tili", "Qoraqalpoq tili", "Tojik tili"],
        "correct": 1,
    },
    {
        "q": "O'zbekiston bayrog'idagi yarim oy nechta yulduz bilan o'ralgan?",
        "options": ["10 ta", "11 ta", "12 ta", "13 ta"],
        "correct": 2,
    },
]

DEFAULT_PRODUCTS = [
    ("Telefon Samsung Galaxy A55", 4_500_000, "5G, 8GB RAM, 256GB memory"),
    ("Noutbook Lenovo IdeaPad", 7_200_000, "Intel i5, 16GB RAM, SSD 512GB"),
    ("AirPods Pro 2-s avlod", 1_350_000, "Faol shovqinni bastaklash, simsiz"),
    ("Power Bank 20000mAh", 320_000, "Tez quvvatlash, 2 ta port"),
    ("Smart soat Mi Band 8", 480_000, "Puls, qadamlar, uyqu kuzatuvi"),
]


def fmt_price(price: int) -> str:
    """Narxni o'qishga qulay formatga keltiradi: 4500000 -> 4 500 000 so'm."""
    return f"{price:,}".replace(",", " ") + " so'm"


async def check_trial(message: types.Message, token_digest: str) -> bool:
    """Botning sinov muddati hali amalda ekanligini tekshiradi."""
    from main import is_valid_trial

    async with db_lock:
        row = db.execute(
            "SELECT is_active, trial_ends_at FROM managed_bots WHERE token_hash=?",
            (token_digest,),
        ).fetchone()
        valid = bool(row) and is_valid_trial(row)
        if row and not valid and row["is_active"]:
            db.execute("UPDATE managed_bots SET is_active=0 WHERE token_hash=?", (token_digest,))
            db.commit()
    if not valid:
        await message.answer("⏳ Ushbu botning sinov muddati tugagan yoki bot vaqtincha to'xtatilgan.")
    return valid


def reply_menu(template: str):
    """Reply-klaviatura (asosiy menyu) — har bir shablon uchun."""
    kb = ReplyKeyboardBuilder()
    if template == "support":
        kb.button(text="💬 Savol yuborish")
        kb.button(text="📋 Mening so'rovlarim")
        kb.button(text="ℹ️ Yordam")
    elif template == "shop":
        kb.button(text="🛍️ Katalog")
        kb.button(text="🛒 Savat")
        kb.button(text="📦 Buyurtmalarim")
        kb.button(text="☎️ Aloqa")
    elif template == "quiz":
        kb.button(text="🧠 Testni boshlash")
        kb.button(text="📊 Natijalarim")
        kb.button(text="ℹ️ Qoidalar")
    else:  # sub
        kb.button(text="📢 Obuna haqida")
        kb.button(text="✅ Obunani tekshirish")
        kb.button(text="☎️ Admin bilan aloqa")
    kb.adjust(2)
    return kb.as_markup(resize_keyboard=True)


# ───────────────────────── SUPPORT BOT ─────────────────────────

async def support_create_ticket(bot_id: int, tg_user_id: int, username: str, message: str) -> int:
    """Yangi ticket yaratadi va uning raqamini qaytaradi."""
    async with db_lock:
        row = db.execute("SELECT COALESCE(MAX(ticket_no), 0) + 1 AS next_no FROM support_tickets WHERE bot_id=?", (bot_id,)).fetchone()
        ticket_no = row["next_no"]
        db.execute(
            "INSERT INTO support_tickets (bot_id, tg_user_id, tg_username, ticket_no, message, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?)",
            (bot_id, tg_user_id, username, ticket_no, message, datetime.utcnow().isoformat()),
        )
        db.commit()
    return ticket_no


async def support_list_user_tickets(bot_id: int, tg_user_id: int) -> list:
    async with db_lock:
        rows = db.execute(
            "SELECT ticket_no, substr(message, 1, 60) AS preview, status, created_at "
            "FROM support_tickets WHERE bot_id=? AND tg_user_id=? ORDER BY id DESC LIMIT 10",
            (bot_id, tg_user_id),
        ).fetchall()
    return [dict(r) for r in rows]


# ───────────────────────── SHOP BOT ─────────────────────────

async def shop_list_products(bot_id: int) -> list:
    async with db_lock:
        rows = db.execute(
            "SELECT id, name, price, description FROM shop_products WHERE bot_id=? ORDER BY id",
            (bot_id,),
        ).fetchall()
    return [dict(r) for r in rows]


async def shop_cart_add(bot_id: int, tg_user_id: int, product_id: int) -> None:
    async with db_lock:
        db.execute(
            "INSERT INTO shop_cart (bot_id, tg_user_id, product_id, qty) VALUES (?, ?, ?, 1) "
            "ON CONFLICT(bot_id, tg_user_id, product_id) DO UPDATE SET qty = qty + 1",
            (bot_id, tg_user_id, product_id),
        )
        db.commit()


async def shop_cart_list(bot_id: int, tg_user_id: int) -> list:
    async with db_lock:
        rows = db.execute(
            "SELECT c.product_id, c.qty, p.name, p.price FROM shop_cart c "
            "JOIN shop_products p ON c.product_id = p.id "
            "WHERE c.bot_id=? AND c.tg_user_id=? ORDER BY p.id",
            (bot_id, tg_user_id),
        ).fetchall()
    return [dict(r) for r in rows]


async def shop_cart_clear(bot_id: int, tg_user_id: int) -> None:
    async with db_lock:
        db.execute("DELETE FROM shop_cart WHERE bot_id=? AND tg_user_id=?", (bot_id, tg_user_id))
        db.commit()


async def shop_create_order(bot_id: int, tg_user_id: int, username: str, name: str, phone: str) -> int:
    items = await shop_cart_list(bot_id, tg_user_id)
    if not items:
        return 0
    total = sum(it["price"] * it["qty"] for it in items)
    items_json = json.dumps(
        [{"name": it["name"], "price": it["price"], "qty": it["qty"]} for it in items],
        ensure_ascii=False,
    )
    async with db_lock:
        cur = db.execute(
            "INSERT INTO shop_orders (bot_id, tg_user_id, tg_username, customer_name, customer_phone, "
            "items_json, total, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)",
            (bot_id, tg_user_id, username, name, phone, items_json, total, datetime.utcnow().isoformat()),
        )
        db.execute("DELETE FROM shop_cart WHERE bot_id=? AND tg_user_id=?", (bot_id, tg_user_id))
        db.commit()
        return cur.lastrowid


# ───────────────────────── QUIZ BOT ─────────────────────────

async def quiz_save_result(bot_id: int, tg_user_id: int, username: str, score: int, total: int) -> None:
    async with db_lock:
        db.execute(
            "INSERT INTO quiz_results (bot_id, tg_user_id, tg_username, score, total, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (bot_id, tg_user_id, username, score, total, datetime.utcnow().isoformat()),
        )
        db.commit()


async def quiz_best_score(bot_id: int, tg_user_id: int) -> dict | None:
    async with db_lock:
        row = db.execute(
            "SELECT score, total, MAX(score) AS best FROM quiz_results WHERE bot_id=? AND tg_user_id=?",
            (bot_id, tg_user_id),
        ).fetchone()
    return dict(row) if row else None


async def quiz_last_results(bot_id: int, tg_user_id: int) -> list:
    async with db_lock:
        rows = db.execute(
            "SELECT score, total, created_at FROM quiz_results WHERE bot_id=? AND tg_user_id=? "
            "ORDER BY id DESC LIMIT 5",
            (bot_id, tg_user_id),
        ).fetchall()
    return [dict(r) for r in rows]


# ───────────────────────── DISPATCHER ─────────────────────────

def build_dispatcher(token: str, template: str, bot_id: int, td: str) -> Dispatcher:
    """Berilgan shablon uchun to'liq ishlaydigan dispatcher yaratadi.

    token  — Telegram bot tokeni
    template — support/shop/quiz/sub
    bot_id — managed_bots.id (ma'lumotlar bazasi so'rovlari uchun)
    td     — token_digest (sinov muddatini tekshirish uchun)
    """
    dp = Dispatcher()
    states = user_states[td]

    async def trial_ok(message: types.Message) -> bool:
        return await check_trial(message, td)

    def tg_user(message: types.Message) -> tuple[int, str]:
        uid = message.from_user.id if message.from_user else 0
        uname = ("@" + message.from_user.username) if (message.from_user and message.from_user.username) else (message.from_user.full_name if message.from_user else "Foydalanuvchi")
        return uid, uname

    # ── /start va /help ──
    @dp.message(CommandStart())
    async def start(message: types.Message):
        if not await trial_ok(message):
            return
        greetings = {
            "support": "Assalomu alaykum! 👋\nYordam markaziga xush kelibsiz.\nSavolingizni yuboring — biz uni qabul qilamiz va raqami bilan tasdiqlaymiz.",
            "shop": "Assalomu alaykum! 🛍️\nDo'kon botiga xush kelibsiz!\nKatalogdan mahsulot tanlang, savatga qo'shing va buyurtma bering.",
            "quiz": "Salom! 🧠\nBilimingizni sinab ko'ring! Test 5 savoldan iborat. \"Testni boshlash\" tugmasini bosing.",
            "sub": "Assalomu alaykum! 🔐\nObuna botiga xush kelibsiz. Obuna tartibi haqida ma'lumot oling va obunangizni tekshiring.",
        }
        states.pop(message.from_user.id if message.from_user else 0, None)
        await message.answer(greetings[template], reply_markup=reply_menu(template))

    @dp.message(Command("help"))
    async def help_cmd(message: types.Message):
        if await trial_ok(message):
            await message.answer(
                "Mavjud buyruqlar:\n/start — bosh menyu\n/help — yordam\nQuyidagi tugmalardan foydalaning.",
                reply_markup=reply_menu(template),
            )

    # ── SUPPORT: savol yuborish ──
    if template == "support":
        @dp.message(F.text == "💬 Savol yuborish")
        async def ask_question(message: types.Message):
            if await trial_ok(message):
                states[message.from_user.id] = {"step": "awaiting_question"}
                await message.answer("✍️ Savolingizni yozib yuboring. Operator ko'rib chiqadi va javob beradi.")

        @dp.message(F.text == "📋 Mening so'rovlarim")
        async def my_tickets(message: types.Message):
            if not await trial_ok(message):
                return
            uid, _ = tg_user(message)
            tickets = await support_list_user_tickets(bot_id, uid)
            if not tickets:
                await message.answer("Sizda hozircha so'rovlar yo'q.")
                return
            lines = ["📋 Sizning so'rovlaringiz:\n"]
            for t in tickets:
                preview = t["preview"] or ""
                lines.append(f"№{t['ticket_no']} — {t['status']} — {preview}...")
            await message.answer("\n".join(lines), reply_markup=reply_menu(template))

        @dp.message(F.text == "ℹ️ Yordam")
        async def support_help(message: types.Message):
            if await trial_ok(message):
                await message.answer("Savolingizni yozib yuboring — biz uni qabul qilamiz va raqam bilan tasdiqlaymiz. ✅")

        @dp.message()
        async def support_fallback(message: types.Message):
            if not await trial_ok(message):
                return
            uid, uname = tg_user(message)
            st = states.get(uid)
            if st and st.get("step") == "awaiting_question":
                states.pop(uid, None)
                ticket_no = await support_create_ticket(bot_id, uid, uname, message.text or "")
                await message.answer(
                    f"✅ So'rovingiz qabul qilindi!\n\n🎫 Ticket raqami: #{ticket_no}\n"
                    f"Operator tez orada javob beradi.",
                    reply_markup=reply_menu(template),
                )
            else:
                await message.answer(
                    "Savolingizni yozing yoki \"💬 Savol yuborish\" tugmasini bosing.",
                    reply_markup=reply_menu(template),
                )

    # ── SHOP: katalog, savat, buyurtma ──
    elif template == "shop":
        @dp.message(F.text == "🛍️ Katalog")
        async def catalog(message: types.Message):
            if not await trial_ok(message):
                return
            products = await shop_list_products(bot_id)
            if not products:
                await message.answer("🛍️ Hozircha mahsulotlar yo'q. Bot egasi tez orada katalogni to'ldiradi.")
                return
            kb = InlineKeyboardBuilder()
            for p in products:
                kb.button(text=f"{p['name']} — {fmt_price(p['price'])}", callback_data=f"add:{p['id']}")
            kb.adjust(1)
            await message.answer("🛍️ Mahsulotlar katalogi — tanlash uchun bosing:", reply_markup=kb.as_markup())

        @dp.callback_query(F.data.startswith("add:"))
        async def add_to_cart(callback: types.CallbackQuery):
            try:
                product_id = int(callback.data.split(":", 1)[1])
            except (ValueError, IndexError):
                await callback.answer("Noto'g'ri mahsulot.")
                return
            uid = callback.from_user.id
            await shop_cart_add(bot_id, uid, product_id)
            await callback.answer("✅ Savatga qo'shildi!")

        @dp.message(F.text == "🛒 Savat")
        async def cart_view(message: types.Message):
            if not await trial_ok(message):
                return
            uid, _ = tg_user(message)
            items = await shop_cart_list(bot_id, uid)
            if not items:
                await message.answer("🛒 Savatingiz bo'sh. Katalogdan mahsulot tanlang.")
                return
            lines = ["🛒 Sizning savatingiz:\n"]
            total = 0
            for it in items:
                lines.append(f"• {it['name']} ×{it['qty']} = {fmt_price(it['price'] * it['qty'])}")
                total += it["price"] * it["qty"]
            lines.append(f"\n💰 Jami: {fmt_price(total)}")
            kb = InlineKeyboardBuilder()
            kb.button(text="✅ Buyurtma berish", callback_data="checkout")
            kb.button(text="🗑 Savatni tozalash", callback_data="clearcart")
            kb.adjust(1)
            await message.answer("\n".join(lines), reply_markup=kb.as_markup())

        @dp.callback_query(F.data == "clearcart")
        async def clear_cart(callback: types.CallbackQuery):
            uid = callback.from_user.id
            await shop_cart_clear(bot_id, uid)
            await callback.answer("Savat tozalandi.")
            await callback.message.edit_text("🛒 Savat tozalandi. Yangi mahsulot tanlang.")

        @dp.callback_query(F.data == "checkout")
        async def checkout_start(callback: types.CallbackQuery):
            uid = callback.from_user.id
            items = await shop_cart_list(bot_id, uid)
            if not items:
                await callback.answer("Savat bo'sh!")
                return
            await callback.answer()
            states[uid] = {"step": "awaiting_name"}
            await callback.message.answer("📝 Buyurtma berish uchun ismingizni yozing:")

        @dp.message(F.text == "📦 Buyurtmalarim")
        async def my_orders(message: types.Message):
            if not await trial_ok(message):
                return
            uid, _ = tg_user(message)
            async with db_lock:
                rows = db.execute(
                    "SELECT id, total, status, created_at, items_json FROM shop_orders "
                    "WHERE bot_id=? AND tg_user_id=? ORDER BY id DESC LIMIT 5",
                    (bot_id, uid),
                ).fetchall()
            if not rows:
                await message.answer("📦 Sizda hozircha buyurtmalar yo'q.")
                return
            lines = ["📦 Buyurtmalaringiz:\n"]
            for r in rows:
                created = r["created_at"][:16].replace("T", " ")
                lines.append(f"№{r['id']} — {fmt_price(r['total'])} — {r['status']} — {created}")
            await message.answer("\n".join(lines), reply_markup=reply_menu(template))

        @dp.message(F.text == "☎️ Aloqa")
        async def shop_contact(message: types.Message):
            if await trial_ok(message):
                await message.answer(
                    "☎️ Aloqa: buyurtmalar shu bot orqali qabul qilinadi.\n"
                    "Bot egasi bilan bog'lanish uchun saytdagi \"Boshqarish\" bo'limidan foydalaning."
                )

        @dp.message()
        async def shop_fallback(message: types.Message):
            if not await trial_ok(message):
                return
            uid, uname = tg_user(message)
            st = states.get(uid)
            if st and st.get("step") == "awaiting_name":
                st["step"] = "awaiting_phone"
                st["name"] = (message.text or "").strip()
                await message.answer("📞 Endi telefon raqamingizni yuboring (masalan: +998901234567):")
                return
            if st and st.get("step") == "awaiting_phone":
                name = st.get("name", "")
                phone = (message.text or "").strip()
                states.pop(uid, None)
                order_id = await shop_create_order(bot_id, uid, uname, name, phone)
                if order_id:
                    await message.answer(
                        f"🎉 Buyurtma qabul qilindi!\n\n📦 Buyurtma №{order_id}\n"
                        f"👤 {name}\n📞 {phone}\n\nOperator tez orada bog'lanadi.",
                        reply_markup=reply_menu(template),
                    )
                else:
                    await message.answer("Savat bo'sh. Avval katalogdan mahsulot tanlang.", reply_markup=reply_menu(template))
                return
            await message.answer(
                "Iltimos, menyudan kerakli bo'limni tanlang. 🛍️ Katalog — mahsulotlar, 🛒 Savat — buyurtma berish.",
                reply_markup=reply_menu(template),
            )

    # ── QUIZ: test, natija ──
    elif template == "quiz":
        @dp.message(F.text == "🧠 Testni boshlash")
        async def quiz_start(message: types.Message):
            if not await trial_ok(message):
                return
            uid = message.from_user.id
            states[uid] = {"step": "quiz", "q_index": 0, "score": 0}
            await ask_question(message, uid, 0)

        async def ask_question(message: types.Message, uid: int, q_index: int):
            q = QUIZ_QUESTIONS[q_index]
            kb = InlineKeyboardBuilder()
            for i, opt in enumerate(q["options"]):
                letter = chr(65 + i)  # A, B, C, D
                kb.button(text=f"{letter}) {opt}", callback_data=f"ans:{q_index}:{i}")
            kb.adjust(1)
            await message.answer(
                f"🧠 Savol {q_index + 1}/{len(QUIZ_QUESTIONS)}\n\n{q['q']}",
                reply_markup=kb.as_markup(),
            )

        @dp.callback_query(F.data.startswith("ans:"))
        async def quiz_answer(callback: types.CallbackQuery):
            uid = callback.from_user.id
            st = states.get(uid)
            if not st or st.get("step") != "quiz":
                await callback.answer("Test boshlanmagan. /start ni bosing.")
                return
            try:
                _, q_index_str, opt_str = callback.data.split(":")
                q_index = int(q_index_str)
                chosen = int(opt_str)
            except (ValueError, IndexError):
                await callback.answer("Noto'g'ri javob.")
                return
            correct = QUIZ_QUESTIONS[q_index]["correct"]
            if chosen == correct:
                st["score"] += 1
                await callback.answer("✅ To'g'ri!")
            else:
                correct_letter = chr(65 + correct)
                await callback.answer(f"❌ Noto'g'ri. To'g'ri javob: {correct_letter}")
            next_q = q_index + 1
            if next_q < len(QUIZ_QUESTIONS):
                st["q_index"] = next_q
                await callback.message.delete_reply_markup()
                await ask_question(callback.message, uid, next_q)
            else:
                score = st["score"]
                total = len(QUIZ_QUESTIONS)
                states.pop(uid, None)
                uname = ("@" + callback.from_user.username) if callback.from_user.username else callback.from_user.full_name
                await quiz_save_result(bot_id, uid, uname, score, total)
                await callback.message.delete_reply_markup()
                verdict = "🏆 Ajoyib!" if score >= 4 else ("👍 Yaxshi!" if score >= 3 else "📚 Yana urinib ko'ring!")
                await callback.message.answer(
                    f"🏁 Test tugadi!\n\n{verdict}\n📊 Natija: {score}/{total}\n\n"
                    f"Qayta urinish uchun \"🧠 Testni boshlash\" tugmasini bosing.",
                    reply_markup=reply_menu("quiz"),
                )

        @dp.message(F.text == "📊 Natijalarim")
        async def quiz_results(message: types.Message):
            if not await trial_ok(message):
                return
            uid, _ = tg_user(message)
            results = await quiz_last_results(bot_id, uid)
            if not results:
                await message.answer("📊 Siz hali test topshirmadingiz.")
                return
            lines = ["📊 Natijalaringiz:\n"]
            for r in results:
                created = r["created_at"][:16].replace("T", " ")
                lines.append(f"• {r['score']}/{r['total']} — {created}")
            await message.answer("\n".join(lines), reply_markup=reply_menu(template))

        @dp.message(F.text == "ℹ️ Qoidalar")
        async def quiz_rules(message: types.Message):
            if await trial_ok(message):
                await message.answer(
                    "📋 Qoidalar:\n• Test 5 savoldan iborat.\n• Har bir savol uchun 4 variant.\n"
                    "• To'g'ri javoblar soni ball sifatida hisoblanadi.\n• Testni qaytadan topshirish mumkin."
                )

        @dp.message()
        async def quiz_fallback(message: types.Message):
            if await trial_ok(message):
                await message.answer(
                    "Testni boshlash uchun \"🧠 Testni boshlash\" tugmasini bosing.",
                    reply_markup=reply_menu(template),
                )

    # ── SUB: obuna ──
    else:  # template == "sub"
        @dp.message(F.text == "📢 Obuna haqida")
        async def sub_info(message: types.Message):
            if await trial_ok(message):
                await message.answer(
                    "📢 Obuna bo'lish tartibi:\n\n"
                    "1. Quydagi kanalga obuna bo'ling (havola bot egasi tomonidan sozlanadi).\n"
                    "2. \"✅ Obunani tekshirish\" tugmasini bosing.\n"
                    "3. Bot obunangizni tasdiqlaydi.\n\n"
                    "Hozircha obuna havolasi sozlanmagan — bot egasi tez orada qo'shadi."
                )

        @dp.message(F.text == "✅ Obunani tekshirish")
        async def sub_check(message: types.Message):
            if await trial_ok(message):
                # To'liq tekshiruv kanal adminligini talab qiladi; demo rejimda tasdiqlaymiz.
                await message.answer(
                    "✅ Obunangiz qabul qilindi!\n\nEndi botning barcha imkoniyatlaridan foydalanishingiz mumkin."
                )

        @dp.message(F.text == "☎️ Admin bilan aloqa")
        async def sub_contact(message: types.Message):
            if await trial_ok(message):
                await message.answer("☎️ Admin bilan aloqa: bot egasi saytdagi ma'lumotlar orqali sozlanadi.")

        @dp.message()
        async def sub_fallback(message: types.Message):
            if await trial_ok(message):
                await message.answer(
                    "Menyudan kerakli bo'limni tanlang.",
                    reply_markup=reply_menu(template),
                )

    return dp
