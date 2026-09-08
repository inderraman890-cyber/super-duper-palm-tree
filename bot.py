import re
import logging
import sqlite3
import os
import io
from datetime import datetime
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile, FSInputFile
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.dispatcher.middlewares.base import BaseMiddleware
import json
import html
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
import os
import tempfile
from pathlib import Path







import secrets
import time
try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.errors import (
        SessionPasswordNeededError,
        PhoneCodeInvalidError,
        PhoneCodeExpiredError,
        PhoneNumberInvalidError,
        PasswordHashInvalidError,
        FloodWaitError,
    )
except ImportError:
    TelegramClient = None
    StringSession = None
    SessionPasswordNeededError = PhoneCodeInvalidError = PhoneNumberInvalidError = PasswordHashInvalidError = FloodWaitError = None




# Optional dependency for the admin Telegram test-login flow:
# pip install telethon

# Bot configuration
TOKEN = os.getenv("BOT_TOKEN", "8558869772:AAH8T_m5KPiuiqmreJsZxCVO0WmE-dUILeA")
ADMIN_TELEGRAM_ID = 8860215592  # Numeric Telegram user ID for admin authorization


CRYPTO_NETWORKS = (
    "USDT_BEP20",
    "USDT_TRC20",
    "USDT_ERC20",
    "USDC_ERC20",
    "ETH",
    "BTC",
    "SOL",
)
SUPPORT_USERNAME = "wadeds"  # Shown in Support only
# Crypto deposit configuration.
# Set these environment variables to your real receiving addresses.
CRYPTO_ADDRESSES = {
    "USDT_BEP20": os.getenv("CRYPTO_USDT_BEP20", ""),
    "USDT_TRC20": os.getenv("CRYPTO_USDT_TRC20", ""),
    "USDT_ERC20": os.getenv("CRYPTO_USDT_ERC20", ""),
    "USDC_ERC20": os.getenv("CRYPTO_USDC_ERC20", ""),
    "ETH": os.getenv("CRYPTO_ETH", ""),
    "BTC": os.getenv("CRYPTO_BTC", ""),
    "SOL": os.getenv("CRYPTO_SOL", ""),
}
MIN_DEPOSIT = 5.0
MAX_DEPOSIT = 50000.0

CREATE_ORDER_EMOJI_ID = "6039641775377748623"
WALLET_EMOJI_ID = "5893473283696759404"
SUPPORT_EMOJI_ID = "5893149782465057649"
PROFILE_EMOJI_ID = "5893224751119208859"
ORDERS_EMOJI_ID = "5893382531037794941"
FACEBOOK_EMOJI_ID = "5323261730283863478"
SNAPCHAT_EMOJI_ID = "5330248916224983855"
DISCORD_EMOJI_ID = "5325612636467903082"
WHATSAPP_EMOJI_ID = "5334998226636390258"
BACK_EMOJI_ID = "5893368370530621889"
CONTACT_EMOJI_ID = "5154511511741269685"
PROMO_CODES_EMOJI_ID = "6041705726206808304"
ADD_BALANCE_EMOJI_ID = "5893473283696759404"

logging.basicConfig(level=logging.INFO)
bot = Bot(token=TOKEN)
dp = Dispatcher()

# --- MULTI-USER / FORCE-JOIN HANDLING ---
# No global task lock is used. Aiogram FSM state is scoped per user/chat,
# so multiple users can run the same workflow at the same time.
class ForceJoinMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):
        user = getattr(event, "from_user", None)
        if not user:
            return await handler(event, data)

        try:
            if is_admin(user.id):
                return await handler(event, data)
        except Exception:
            pass

        if isinstance(event, types.CallbackQuery):
            callback_data = event.data or ""

            if callback_data in {"force_join_check", "main_menu"}:
                return await handler(event, data)

            if not await user_has_joined_required_channels(user.id):
                await event.answer(
                    "Join the required channels first.",
                    show_alert=True
                )
                await show_force_join_for_callback(event)
                return

        elif isinstance(event, types.Message):
            raw = (event.text or "").strip()

            if raw.startswith("/start"):
                return await handler(event, data)

            if not await user_has_joined_required_channels(user.id):
                await send_force_join_prompt(user.id)
                return

        return await handler(event, data)


dp.callback_query.middleware(ForceJoinMiddleware())
dp.message.middleware(ForceJoinMiddleware())

# FSM States for Crypto Add Balance and Promo Code input
class DepositState(StatesGroup):
    waiting_for_amount = State()
    waiting_for_txhash = State()
    waiting_for_proof = State()

class PromoState(StatesGroup):
    waiting_for_code = State()

class AdminState(StatesGroup):
    waiting_for_force_join_channel = State()
    waiting_for_purchase_channel = State()
    waiting_for_admin_id = State()
    waiting_for_admin_remove_id = State()
    waiting_for_payment_method_settings = State()
    waiting_for_user_id = State()
    waiting_for_history_user_id = State()
    waiting_for_balance_change = State()
    waiting_for_broadcast = State()
    waiting_for_crypto_address = State()
    waiting_for_payment_group = State()
    waiting_for_payment_limit = State()
    waiting_for_promo_create = State()
    waiting_for_deposit_limits = State()
    waiting_for_category_name = State()
    waiting_for_category_style = State()
    waiting_for_subcategory_name = State()
    waiting_for_subcategory_style = State()
    waiting_for_product_details = State()
    waiting_for_account_username = State()
    waiting_for_account_password = State()
    waiting_for_account_email = State()
    waiting_for_account_email_password = State()
    waiting_for_account_2fa = State()



# --- ENCRYPTED ACCOUNT CREDENTIAL VAULT ---
# Sensitive account credentials are encrypted outside bot.db.
# The master key lives in CREDENTIAL_VAULT_KEY_FILE and never in SQLite.
# The buyer receives credentials only in a private message.
#
# To initialize the key once:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Put that value in the environment variable CREDENTIAL_VAULT_KEY, OR let this
# code create a local key file on first startup when the variable is absent.
#
# The vault file should be protected like any other secret.

CREDENTIAL_VAULT_FILE = Path("account_credentials.vault")
CREDENTIAL_VAULT_KEY_FILE = Path("credential_vault.key")


def _credential_vault_key() -> bytes:
    env_key = os.getenv("CREDENTIAL_VAULT_KEY", "").strip()
    if env_key:
        key = env_key.encode("ascii")
        Fernet(key)  # validate
        return key

    if CREDENTIAL_VAULT_KEY_FILE.exists():
        key = CREDENTIAL_VAULT_KEY_FILE.read_bytes().strip()
        Fernet(key)
        return key

    key = Fernet.generate_key()
    fd, tmp_name = tempfile.mkstemp(
        prefix=".credential_vault.",
        dir=str(CREDENTIAL_VAULT_KEY_FILE.parent)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, CREDENTIAL_VAULT_KEY_FILE)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass

    try:
        os.chmod(CREDENTIAL_VAULT_KEY_FILE, 0o600)
    except OSError:
        pass

    logging.warning(
        "Generated credential_vault.key. Protect this file; it is required to decrypt account credentials."
    )
    return key


def _load_credential_vault() -> dict:
    if not CREDENTIAL_VAULT_FILE.exists():
        return {"version": 1, "entries": {}}

    try:
        encrypted = CREDENTIAL_VAULT_FILE.read_bytes()
        plain = Fernet(_credential_vault_key()).decrypt(encrypted)
        vault = json.loads(plain.decode("utf-8"))
        if not isinstance(vault, dict) or vault.get("version") != 1:
            raise RuntimeError("Unsupported credential vault format.")
        vault.setdefault("entries", {})
        return vault
    except InvalidToken as exc:
        raise RuntimeError("Credential vault key is invalid or the vault is corrupted.") from exc


def _save_credential_vault(vault: dict) -> None:
    plain = json.dumps(
        vault, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    encrypted = Fernet(_credential_vault_key()).encrypt(plain)

    fd, tmp_name = tempfile.mkstemp(
        prefix=".account_credentials.",
        dir=str(CREDENTIAL_VAULT_FILE.parent)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(encrypted)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, CREDENTIAL_VAULT_FILE)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass

    try:
        os.chmod(CREDENTIAL_VAULT_FILE, 0o600)
    except OSError:
        pass



def load_account_credentials(account_id: str):
    """Load and decrypt a credential-vault record if the current vault supports it."""
    # The vault format used by this project stores encrypted JSON records.
    # Reuse the same key/file primitives as save_account_credentials.
    if not CREDENTIAL_VAULT_FILE.exists():
        return None

    try:
        # Prefer an existing vault helper if the source exposes one.
        if "load_vault" in globals():
            vault = load_vault()
            value = vault.get(str(account_id))
            return value if isinstance(value, dict) else None

        # Fallback for the project's Fernet-based vault.
        from cryptography.fernet import Fernet
        key = CREDENTIAL_VAULT_KEY.read_bytes()
        fernet = Fernet(key)
        raw = CREDENTIAL_VAULT_FILE.read_bytes()
        if not raw:
            return None
        payload = json.loads(fernet.decrypt(raw).decode("utf-8"))
        value = payload.get(str(account_id))
        return value if isinstance(value, dict) else None
    except Exception:
        logging.exception("Credential vault read failed")
        return None


def save_account_credentials(account_id: str, credentials: dict[str, str]) -> None:
    vault = _load_credential_vault()
    vault["entries"][str(account_id)] = credentials
    _save_credential_vault(vault)


def get_account_credentials(account_id: str) -> dict[str, str] | None:
    vault = _load_credential_vault()
    entry = vault["entries"].get(str(account_id))
    return dict(entry) if isinstance(entry, dict) else None


def delete_account_credentials(account_id: str) -> None:
    vault = _load_credential_vault()
    vault["entries"].pop(str(account_id), None)
    _save_credential_vault(vault)


async def _delete_delivery_message_later(chat_id: int, message_id: int, delay: int = 300):
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
    except Exception:
        logging.exception("Could not auto-delete credential delivery message")


async def deliver_credentials_privately(
    user_id: int,
    item_title: str,
    order_id: str,
    credentials: dict[str, str],
) -> bool:
    """Deliver purchased credentials privately with premium custom-emoji styling.

    The sensitive delivery message is automatically deleted after 5 minutes.
    """
    fields = [
        ("Username", credentials.get("username", "")),
        ("Password", credentials.get("password", "")),
        ("Email", credentials.get("email", "")),
        ("Email Password", credentials.get("email_password", "")),
        ("2FA", credentials.get("two_fa_code", credentials.get("two_fa", ""))),
    ]

    lines = [
        rich_emoji("6041705726206808304", "🔐") + " <b>Private Account Delivery</b>",
        "",
        rich_emoji("5893168654551355607", "📦") +
        f" <b>Item:</b> {html.escape(str(item_title))}",
        rich_emoji("5893048571560726748", "🧾") +
        f" <b>Order ID:</b> <code>{html.escape(str(order_id))}</code>",
        "",
    ]

    field_icons = {
        "Username": ("5033259521208747582", "👤"),
        "Password": ("5893149782465057649", "🔑"),
        "Email": ("5893376775781617954", "📧"),
        "Email Password": ("5893048571560726748", "🔐"),
        "2FA": ("5902335789798265487", "🛡️"),
    }

    for label, value in fields:
        safe_value = html.escape(str(value or "—"))
        icon_id, fallback = field_icons.get(label, ("5893168654551355607", "•"))
        lines.append(
            f"{rich_emoji(icon_id, fallback)} <b>{label}:</b> "
            f"<tg-spoiler><code>{safe_value}</code></tg-spoiler>"
        )

    lines.extend([
        "",
        rich_emoji("5893048571560726748", "⚠️") +
        " <b>Save these details now.</b>",
        "This delivery message will be automatically deleted after <b>5 minutes</b>.",
    ])

    message_text = "\n".join(lines)

    try:
        sent = await bot.send_message(
            chat_id=user_id,
            text=message_text,
            parse_mode="HTML",
        )
        asyncio.create_task(
            _delete_delivery_message_later(
                int(user_id), sent.message_id, 300
            )
        )
        return True

    except Exception as exc:
        # Telegram can reject a custom emoji document ID. Retry this delivery
        # without custom emoji entities so the credentials still arrive.
        logging.warning(
            "Premium custom-emoji delivery failed, retrying plain: %s",
            exc
        )
        plain = re.sub(
            r"<tg-emoji\b[^>]*>(.*?)</tg-emoji>",
            r"\1",
            message_text,
            flags=re.DOTALL | re.IGNORECASE
        )
        try:
            sent = await bot.send_message(
                chat_id=user_id,
                text=plain,
                parse_mode="HTML",
            )
            asyncio.create_task(
                _delete_delivery_message_later(
                    int(user_id), sent.message_id, 300
                )
            )
            return True
        except Exception:
            logging.exception(
                "Private credential delivery failed for user %s",
                user_id
            )
            return False


# --- DATABASE SETUP ---
DEFAULT_CATEGORY_STICKERS = {
    "instagram": "5319160079465857105",
    "telegram": "5330237710655306682",
    "tiktok": "5327982530702359565",
    "whatsapp": "5334998226636390258",
    "x": "5303397519424771188",
    "facebook": "5323261730283863478",
    "snapchat": "5330248916224983855",
    "discord": "5325612636467903082",
}

def init_db():
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id TEXT UNIQUE,
        username TEXT,
        balance REAL DEFAULT 0.0,
        total_spent REAL DEFAULT 0.0,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS admins (
        telegram_id TEXT PRIMARY KEY,
        role TEXT NOT NULL DEFAULT 'admin',
        added_by TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute(
        "INSERT OR IGNORE INTO admins (telegram_id, role, added_by) VALUES (?, 'owner', ?)",
        (str(ADMIN_TELEGRAM_ID), str(ADMIN_TELEGRAM_ID))
    )
    # Migration for existing bot.db files
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN total_spent REAL DEFAULT 0.0")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0.0")
    except Exception:
        pass
    cursor.execute("""CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        telegram_id TEXT,
        category TEXT,
        item_title TEXT,
        price REAL,
        status TEXT DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        category TEXT,
        title TEXT,
        price REAL,
        stock_count INTEGER DEFAULT 0,
        credentials_format TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS store_categories (
        key TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        button_style TEXT DEFAULT 'primary',
        sticker_id TEXT,
        sort_order INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS store_subcategories (
        id TEXT PRIMARY KEY,
        category_key TEXT NOT NULL,
        name TEXT NOT NULL,
        button_style TEXT DEFAULT 'primary',
        sticker_id TEXT,
        sort_order INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(category_key, name)
    )""")
    try:
        cursor.execute("ALTER TABLE accounts ADD COLUMN subcategory_id TEXT")
    except Exception:
        pass
    cursor.execute("""CREATE TABLE IF NOT EXISTS deposits (
        id TEXT PRIMARY KEY,
        telegram_id TEXT,
        username TEXT,
        amount REAL,
        txn_id TEXT UNIQUE,
        screenshot_url TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    try:
        cursor.execute("ALTER TABLE deposits ADD COLUMN screenshot_url TEXT")
    except Exception:
        pass
    cursor.execute("""CREATE TABLE IF NOT EXISTS wallet_transactions (
        id TEXT PRIMARY KEY,
        telegram_id TEXT,
        type TEXT,
        title TEXT,
        amount REAL,
        balance_before REAL,
        balance_after REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reference_id TEXT
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS promo_codes (
        id TEXT PRIMARY KEY,
        code TEXT UNIQUE,
        reward_type TEXT DEFAULT 'fixed',
        reward_value REAL,
        max_uses INTEGER DEFAULT 50,
        used_count INTEGER DEFAULT 0,
        per_user_limit INTEGER DEFAULT 1,
        min_wallet_req REAL DEFAULT 0,
        expires_at TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS promo_usages (
        id TEXT PRIMARY KEY,
        promo_id TEXT,
        code TEXT,
        telegram_id TEXT,
        reward_amount REAL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS bot_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")
    cursor.execute(
        "INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?, ?)",
        ("purchase_channel_chat_id", "")
    )
    cursor.execute(
        "INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?, ?)",
        ("purchase_channel_link", "")
    )
    cursor.execute("""CREATE TABLE IF NOT EXISTS banned_users (
        telegram_id TEXT PRIMARY KEY,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS force_join_channels (
        id TEXT PRIMARY KEY,
        chat_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        username TEXT,
        join_link TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    for _network, _value in CRYPTO_ADDRESSES.items():
        cursor.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?, ?)", (f"crypto_{_network}", _value))
    cursor.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES ('min_deposit', ?)", (str(MIN_DEPOSIT),))
    cursor.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES ('max_deposit', ?)", (str(MAX_DEPOSIT),))
    defaults = [
        ("instagram","Instagram"),("telegram","Telegram"),("tiktok","TikTok"),
        ("whatsapp","WhatsApp"),("x","X (Twitter)"),("facebook","Facebook"),
        ("snapchat","Snapchat"),("discord","Discord")
    ]
    for i,(key,name) in enumerate(defaults):
        sticker_id = DEFAULT_CATEGORY_STICKERS.get(key, "")
        cursor.execute(
            "INSERT OR IGNORE INTO store_categories"
            "(key,name,button_style,sticker_id,sort_order,enabled) "
            "VALUES(?,?,?,?,?,1)",
            (key,name,"primary",sticker_id,i)
        )
        # Restore the original Create Order sticker only when the DB value is
        # empty. This does not overwrite any custom sticker chosen by admin.
        cursor.execute(
            "UPDATE store_categories SET sticker_id=? "
            "WHERE key=? AND (sticker_id IS NULL OR sticker_id='')",
            (sticker_id,key)
        )

    # ---- Post-create schema migration for older bot.db files ----
    # SQLite CREATE TABLE IF NOT EXISTS does not modify an existing table.
    # Add every column used by the current bot only after the table exists.
    required_columns = {
        "users": [
            ("balance", "REAL"),
            ("total_spent", "REAL"),
        ],
        "orders": [
            ("category", "TEXT"),
            ("item_title", "TEXT"),
            ("price", "REAL"),
            ("status", "TEXT"),
            ("created_at", "TIMESTAMP"),
        ],
        "accounts": [
            ("credentials_format", "TEXT"),
            ("subcategory_id", "TEXT"),
            ("stock_count", "INTEGER"),
        ],
        "deposits": [
            ("username", "TEXT"),
            ("screenshot_url", "TEXT"),
            ("status", "TEXT"),
            ("created_at", "TIMESTAMP"),
        ],
        "wallet_transactions": [
            ("reference_id", "TEXT"),
            ("created_at", "TIMESTAMP"),
        ],
    }

    for _table, _columns in required_columns.items():
        _existing = {r[1] for r in cursor.execute(f"PRAGMA table_info({_table})").fetchall()}
        for _column, _definition in _columns:
            if _column not in _existing:
                cursor.execute(
                    f"ALTER TABLE {_table} ADD COLUMN {_column} {_definition}"
                )

    # Backfill safe values for legacy rows.
    cursor.execute("UPDATE orders SET status='completed' WHERE status IS NULL OR status=''")
    cursor.execute("UPDATE orders SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL")
    cursor.execute("UPDATE accounts SET stock_count=0 WHERE stock_count IS NULL")

    conn.commit()
    conn.close()

init_db()

def ensure_column(table_name, column_name, column_definition):
    """Add a missing SQLite column without destroying existing user data.

    SQLite cannot ALTER TABLE ADD COLUMN with a non-constant default such as
    CURRENT_TIMESTAMP. For those columns we add them without the default and
    backfill existing rows explicitly.
    """
    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
        if column_name in cols:
            return

        # SQLite rejects CURRENT_TIMESTAMP as an ADD COLUMN default.
        if "CURRENT_TIMESTAMP" in column_definition.upper():
            safe_definition = column_definition
            safe_definition = safe_definition.replace(
                "DEFAULT CURRENT_TIMESTAMP", ""
            ).replace(
                "default current_timestamp", ""
            ).strip()
            conn.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {safe_definition}"
            )
            conn.execute(
                f"UPDATE {table_name} SET {column_name}=CURRENT_TIMESTAMP "
                f"WHERE {column_name} IS NULL"
            )
        else:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
        conn.commit()
    finally:
        conn.close()


def migrate_database():
    """
    Upgrade older bot.db files in-place.

    The runtime logs showed older schemas missing:
      - promo_codes.reward_type
      - deposits.username
      - accounts.stock_count

    CREATE TABLE IF NOT EXISTS does not add columns to an existing table,
    which was the reason those handlers crashed.
    """
    ensure_column("deposits", "username", "TEXT")
    ensure_column("deposits", "screenshot_url", "TEXT")
    ensure_column("deposits", "status", "TEXT DEFAULT 'pending'")
    ensure_column("deposits", "created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    ensure_column("deposits", "crypto_network", "TEXT")

    # Older bot.db files may have promo_codes without the newer primary-key
    # style `id` column. Add it and backfill stable IDs for existing records.
    ensure_column("promo_codes", "id", "TEXT")
    ensure_column("promo_codes", "reward_type", "TEXT DEFAULT 'fixed'")
    ensure_column("promo_codes", "reward_value", "REAL DEFAULT 0")
    ensure_column("promo_codes", "max_uses", "INTEGER DEFAULT 50")
    ensure_column("promo_codes", "used_count", "INTEGER DEFAULT 0")
    ensure_column("promo_codes", "per_user_limit", "INTEGER DEFAULT 1")
    ensure_column("promo_codes", "min_wallet_req", "REAL DEFAULT 0")
    ensure_column("promo_codes", "expires_at", "TEXT")
    ensure_column("promo_codes", "is_active", "INTEGER DEFAULT 1")
    ensure_column("promo_codes", "created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    ensure_column("accounts", "stock_count", "INTEGER DEFAULT 0")

    # Backfill stock_count when the old accounts table stores individual
    # account rows. Existing non-null rows become one unit of stock.
    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()}
        if "stock_count" in cols:
            # Only fill missing/zero stock for existing account rows.
            conn.execute("UPDATE accounts SET stock_count=1 WHERE stock_count IS NULL")
        conn.commit()
    finally:
        conn.close()


migrate_database()

# Backfill legacy promo IDs. SQLite cannot add a new primary-key constraint
# through ALTER TABLE, but the application only needs unique IDs here.
def backfill_promo_ids():
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        cols={row[1] for row in conn.execute("PRAGMA table_info(promo_codes)").fetchall()}
        if "id" not in cols:
            return
        rows=conn.execute(
            "SELECT rowid, code FROM promo_codes WHERE id IS NULL OR id=''"
        ).fetchall()
        for rowid, code in rows:
            promo_id=f"PROMO-LEGACY-{rowid}"
            conn.execute(
                "UPDATE promo_codes SET id=? WHERE rowid=?",
                (promo_id,rowid)
            )
        conn.commit()
    finally:
        conn.close()


backfill_promo_ids()

logging.info("Database schema migration completed.")
logging.info("Encrypted credential vault ready.")
def ensure_payment_settings():
    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS payment_methods (
            network TEXT PRIMARY KEY,
            min_amount REAL DEFAULT 5,
            max_amount REAL DEFAULT 50000,
            max_pending INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS bot_payment_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        for _network in CRYPTO_NETWORKS:
            conn.execute(
                "INSERT OR IGNORE INTO payment_methods "
                "(network,min_amount,max_amount,max_pending,enabled) VALUES (?,?,?,?,1)",
                (_network, MIN_DEPOSIT, MAX_DEPOSIT, 1)
            )
        conn.execute(
            "INSERT OR IGNORE INTO bot_payment_settings (key,value) VALUES "
            "('review_group_chat_id','')"
        )
        conn.execute(
            "INSERT OR IGNORE INTO bot_payment_settings (key,value) VALUES "
            "('review_group_link','')"
        )
        conn.commit()
    finally:
        conn.close()


def get_payment_setting(key, default=""):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        row=conn.execute(
            "SELECT value FROM bot_payment_settings WHERE key=?", (key,)
        ).fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def set_payment_setting(key, value):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute(
            "INSERT INTO bot_payment_settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key,str(value))
        )
        conn.commit()
    finally:
        conn.close()


def get_payment_method(network):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        row=conn.execute(
            "SELECT min_amount,max_amount,max_pending,enabled "
            "FROM payment_methods WHERE network=?", (network,)
        ).fetchone()
        return row or (MIN_DEPOSIT, MAX_DEPOSIT, 1, 1)
    finally:
        conn.close()


def set_payment_method(network, minimum, maximum, max_pending, enabled=1):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute(
            "INSERT INTO payment_methods(network,min_amount,max_amount,max_pending,enabled) "
            "VALUES(?,?,?,?,?) ON CONFLICT(network) DO UPDATE SET "
            "min_amount=excluded.min_amount,max_amount=excluded.max_amount,"
            "max_pending=excluded.max_pending,enabled=excluded.enabled",
            (network,minimum,maximum,max_pending,enabled)
        )
        conn.commit()
    finally:
        conn.close()


ensure_payment_settings()



def get_bot_setting(key, default=""):
    conn = sqlite3.connect("bot.db", timeout=30)
    row = conn.execute("SELECT value FROM bot_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default

def set_bot_setting(key, value):
    conn = sqlite3.connect("bot.db", timeout=30)
    conn.execute("INSERT INTO bot_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    conn.commit(); conn.close()

def reload_payment_settings():
    global MIN_DEPOSIT, MAX_DEPOSIT
    for _network in CRYPTO_ADDRESSES:
        CRYPTO_ADDRESSES[_network] = get_bot_setting(f"crypto_{_network}", CRYPTO_ADDRESSES[_network])
    try: MIN_DEPOSIT = float(get_bot_setting("min_deposit", MIN_DEPOSIT))
    except (TypeError, ValueError): pass
    try: MAX_DEPOSIT = float(get_bot_setting("max_deposit", MAX_DEPOSIT))
    except (TypeError, ValueError): pass

reload_payment_settings()

def _strip_custom_emoji_markup(reply_markup):
    """Return the same keyboard without custom-emoji button icons.

    Telegram can return DOCUMENT_INVALID when an old/invalid custom emoji
    document ID is attached to a button. Removing only the icon preserves the
    buttons and callback actions.
    """
    if reply_markup is None:
        return None

    try:
        new_rows = []
        for row in reply_markup.inline_keyboard:
            new_row = []
            for button in row:
                try:
                    # aiogram models are Pydantic models.
                    new_row.append(
                        button.model_copy(
                            update={"icon_custom_emoji_id": None}
                        )
                    )
                except Exception:
                    data = button.model_dump(exclude_none=True)
                    data.pop("icon_custom_emoji_id", None)
                    new_row.append(InlineKeyboardButton(**data))
            new_rows.append(new_row)
        return InlineKeyboardMarkup(inline_keyboard=new_rows)
    except Exception:
        logging.exception("Could not sanitize inline keyboard")
        return None


def _strip_custom_emoji_entities(text):
    """Remove Telegram custom-emoji entity wrappers while keeping their emoji."""
    return re.sub(
        r"<tg-emoji\b[^>]*>(.*?)</tg-emoji>",
        r"\1",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )


async def _send_safe_text(chat_id, text, reply_markup=None):
    """Final send helper: try rich text, then plain custom-emoji-free text."""
    try:
        return await bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode="HTML",
            reply_markup=reply_markup
        )
    except Exception:
        plain = _strip_custom_emoji_entities(text)
        plain_kb = _strip_custom_emoji_markup(reply_markup)
        return await bot.send_message(
            chat_id=chat_id,
            text=plain,
            parse_mode="HTML",
            reply_markup=plain_kb
        )


async def safe_edit(callback: types.CallbackQuery, text: str, reply_markup=None):
    """Edit current panel; automatically recover from bad custom emoji IDs/entities."""
    message = callback.message
    if not message:
        try:
            await _send_safe_text(callback.from_user.id, text, reply_markup)
        except Exception:
            logging.exception("safe_edit: initial send failed")
        return

    plain_text = _strip_custom_emoji_entities(text)
    safe_markup = _strip_custom_emoji_markup(reply_markup)

    # Attempt 1: original rich content.
    try:
        if message.text is not None:
            await message.edit_text(text, parse_mode="HTML", reply_markup=reply_markup)
            return
        if (
            (message.photo or message.video or message.animation
             or message.audio or message.document)
            and message.caption is not None
        ):
            await message.edit_caption(
                caption=text, parse_mode="HTML", reply_markup=reply_markup
            )
            return
    except TelegramBadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return
        logging.warning("safe_edit rich attempt failed: %s", exc)
    except Exception as exc:
        logging.warning("safe_edit rich attempt failed: %s", exc)

    # Attempt 2: remove all custom emoji IDs/entities. This directly handles
    # DOCUMENT_INVALID and ENTITY_TEXT_INVALID.
    try:
        if message.text is not None:
            await message.edit_text(
                plain_text, parse_mode="HTML", reply_markup=safe_markup
            )
            return
        if (
            (message.photo or message.video or message.animation
             or message.audio or message.document)
            and message.caption is not None
        ):
            await message.edit_caption(
                caption=plain_text, parse_mode="HTML", reply_markup=safe_markup
            )
            return
    except TelegramBadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return
        logging.warning("safe_edit sanitized edit failed: %s", exc)
    except Exception as exc:
        logging.warning("safe_edit sanitized edit failed: %s", exc)

    # Attempt 3: delete stale/unsupported media and replace with one clean text
    # message. No recursive callback.message.answer() fallback.
    try:
        await message.delete()
    except Exception:
        pass

    try:
        await bot.send_message(
            chat_id=message.chat.id,
            text=plain_text,
            parse_mode="HTML",
            reply_markup=safe_markup
        )
    except Exception:
        logging.exception("safe_edit clean replacement failed")



def log_transaction(telegram_id, txn_type, title, amount, b_before, b_after, ref_id):
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    txn_id = f"TXN-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("""
        INSERT INTO wallet_transactions (id, telegram_id, type, title, amount, balance_before, balance_after, reference_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (txn_id, str(telegram_id), txn_type, title, amount, b_before, b_after, ref_id))
    conn.commit()
    conn.close()

# --- KEYBOARDS ---
def get_main_menu(user_id=None):
    keyboard = [
        [
            InlineKeyboardButton(text="Create Order", callback_data="create_order", style="primary", icon_custom_emoji_id=CREATE_ORDER_EMOJI_ID),
            InlineKeyboardButton(text="Wallet", callback_data="wallet", style="primary", icon_custom_emoji_id=WALLET_EMOJI_ID)
        ],
        [
            InlineKeyboardButton(text="Orders", callback_data="orders", style="primary", icon_custom_emoji_id=ORDERS_EMOJI_ID),
            InlineKeyboardButton(text="Profile", callback_data="profile", style="primary", icon_custom_emoji_id=PROFILE_EMOJI_ID)
        ],
        [
            InlineKeyboardButton(text="Support", callback_data="support", style="danger", icon_custom_emoji_id=SUPPORT_EMOJI_ID)
        ]
    ]
    if user_id and is_admin(user_id):
        keyboard.append([
            InlineKeyboardButton(text="Admin Panel", callback_data="admin_panel", style="danger", icon_custom_emoji_id="5039539210072097557")
        ])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)

def get_wallet_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Add Balance", callback_data="add_balance", style="primary", icon_custom_emoji_id=ADD_BALANCE_EMOJI_ID),
            InlineKeyboardButton(text="Promo Code", callback_data="promocodes", style="primary", icon_custom_emoji_id=PROMO_CODES_EMOJI_ID)
        ],
        [
            InlineKeyboardButton(text="Balance History", callback_data="balance_history_1", style="primary", icon_custom_emoji_id="5893382531037794941"),
            InlineKeyboardButton(text="Back", callback_data="main_menu", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)
        ]
    ])

def get_admin_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="Users",
                callback_data="admin_users",
                style="primary",
                icon_custom_emoji_id=PROFILE_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Payments",
                callback_data="admin_deposits",
                style="primary",
                icon_custom_emoji_id=ADD_BALANCE_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="Store & Stock",
                callback_data="admin_store",
                style="primary",
                icon_custom_emoji_id=CREATE_ORDER_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Promo Codes",
                callback_data="admin_promos",
                style="primary",
                icon_custom_emoji_id=PROMO_CODES_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="User History",
                callback_data="admin_user_history",
                style="primary",
                icon_custom_emoji_id=ORDERS_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Broadcast",
                callback_data="admin_broadcast",
                style="primary",
                icon_custom_emoji_id=CREATE_ORDER_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="Bot Stats",
                callback_data="admin_stats",
                style="primary",
                icon_custom_emoji_id=ORDERS_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Crypto Settings",
                callback_data="admin_crypto_settings",
                style="primary",
                icon_custom_emoji_id=ADD_BALANCE_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="Manage Admins",
                callback_data="admin_manage_admins",
                style="primary",
                icon_custom_emoji_id=PROFILE_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Force Join",
                callback_data="admin_force_join",
                style="primary",
                icon_custom_emoji_id=CREATE_ORDER_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="Purchase Channel",
                callback_data="admin_purchase_channel",
                style="primary",
                icon_custom_emoji_id=CREATE_ORDER_EMOJI_ID
            ),
            InlineKeyboardButton(
                text="Payment Channel",
                callback_data="admin_payment_channel",
                style="primary",
                icon_custom_emoji_id=ADD_BALANCE_EMOJI_ID
            )
        ],
        [
            InlineKeyboardButton(
                text="Back to Main Menu",
                callback_data="main_menu",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]
    ])


# --- COMMAND /START ---
def get_welcome_text():
    return (
        "<tg-emoji emoji-id='6041705726206808304'>🔰</tg-emoji> "
        "<b>Aged Counter | #1 Aged Account Platform</b>"
        + chr(10) + chr(10)
        + "<i>Your trusted source for premium aged accounts across multiple platforms.</i>"
        + chr(10) + chr(10)
        + "<tg-emoji emoji-id='6039641775377748623'>✨</tg-emoji> "
        "<b>Premium &amp; Quality Accounts</b>" + chr(10)
        + "<tg-emoji emoji-id='5893168654551355607'>🌐</tg-emoji> "
        "<b>Multiple Platforms Available</b>" + chr(10)
        + "<tg-emoji emoji-id='5893048571560726748'>⚡</tg-emoji> "
        "<b>Fast &amp; Reliable Delivery</b>" + chr(10)
        + "<tg-emoji emoji-id='5902335789798265487'>🌍</tg-emoji> "
        "<b>Trusted by Buyers Worldwide</b>" + chr(10)
        + "<tg-emoji emoji-id='5893149782465057649'>💬</tg-emoji> "
        "<b>24/7 Support Available</b>"
    )



async def edit_or_send_menu(callback: types.CallbackQuery, text: str, reply_markup=None, parse_mode="HTML"):
    """Keep admin navigation in one message instead of creating a new message."""
    try:
        await callback.message.edit_text(
            text,
            parse_mode=parse_mode,
            reply_markup=reply_markup
        )
    except Exception:
        try:
            await callback.message.edit_caption(
                caption=text,
                parse_mode="HTML",
                reply_markup=reply_markup
            )
        except Exception:
            await callback.message.answer(
                text,
                parse_mode="HTML",
                reply_markup=reply_markup
            )


async def delete_user_message_later(message: types.Message, delay: int = 30):
    """Delete an admin's temporary text input after a short delay."""
    await asyncio.sleep(delay)
    try:
        await message.delete()
    except Exception:
        pass


def schedule_user_message_cleanup(message: types.Message, delay: int = 30):
    asyncio.create_task(delete_user_message_later(message, delay))


async def begin_admin_input(callback: types.CallbackQuery, state: FSMContext, fsm_state, prompt_text: str):
    """Edit the admin panel into a waiting state and create one temporary input prompt."""
    await state.set_state(fsm_state)
    await state.update_data(
        admin_panel_chat_id=callback.message.chat.id,
        admin_panel_message_id=callback.message.message_id,
    )
    await safe_edit(
        callback,
        prompt_text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Cancel",
                callback_data="admin_panel",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )


async def finish_admin_input(state: FSMContext, text: str, reply_markup=None):
    """Finish an admin input flow safely for text, media, deleted, or stale panels."""
    data = await state.get_data()
    chat_id = data.get("admin_panel_chat_id")
    message_id = data.get("admin_panel_message_id")

    if not chat_id or not message_id:
        await state.clear()
        return False

    # 1) Normal text-message edit.
    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode="HTML",
            reply_markup=reply_markup,
        )
        await state.clear()
        return True
    except TelegramBadRequest as exc:
        err = str(exc).lower()
        if "message is not modified" in err:
            await state.clear()
            return True
        if "there is no text in the message to edit" not in err:
            logging.warning("finish_admin_input text edit failed: %s", exc)
    except Exception as exc:
        logging.warning("finish_admin_input text edit failed: %s", exc)

    # 2) Media message with a caption.
    try:
        await bot.edit_message_caption(
            chat_id=chat_id,
            message_id=message_id,
            caption=text,
            parse_mode="HTML",
            reply_markup=reply_markup,
        )
        await state.clear()
        return True
    except TelegramBadRequest as exc:
        err = str(exc).lower()
        if "message is not modified" in err:
            await state.clear()
            return True
        logging.warning("finish_admin_input caption edit failed: %s", exc)
    except Exception as exc:
        logging.warning("finish_admin_input caption edit failed: %s", exc)

    # 3) The stored panel may already be gone or be a non-editable message.
    # Replace it with one clean admin panel instead of throwing another error.
    try:
        try:
            await bot.delete_message(
                chat_id=chat_id,
                message_id=message_id,
            )
        except Exception:
            pass

        await bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode="HTML",
            reply_markup=reply_markup,
        )
        await state.clear()
        return True
    except Exception:
        logging.exception("finish_admin_input replacement send failed")
        await state.clear()
        return False



# --- FORCE JOIN SYSTEM ---
def get_force_join_channels(enabled_only=True):
    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        query = (
            "SELECT id, chat_id, title, username, join_link, enabled "
            "FROM force_join_channels"
        )
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY created_at ASC, id ASC"
        return conn.execute(query).fetchall()
    except sqlite3.Error:
        logging.exception("Force-join channel lookup failed")
        return []
    finally:
        conn.close()


async def user_has_joined_required_channels(user_id: int) -> bool:
    """Return True only when the user is a member of every enabled channel.

    Telegram can refuse member lookups when the bot lacks the ability to see
    hidden channel/supergroup members. Treat that as a configuration problem,
    not as proof that the user has not joined.
    """
    channels = get_force_join_channels(enabled_only=True)
    if not channels:
        return True

    for channel_id, chat_id, title, username, join_link, enabled in channels:
        try:
            member = await bot.get_chat_member(
                chat_id=chat_id,
                user_id=user_id
            )
            status = str(getattr(member, "status", "")).lower()

            if status in {"creator", "administrator", "member"}:
                continue

            if status == "restricted" and bool(
                getattr(member, "is_member", False)
            ):
                continue

            return False

        except TelegramBadRequest as exc:
            err = str(exc).lower()

            if "member list is inaccessible" in err:
                logging.error(
                    "Force-join membership lookup unavailable for %s. "
                    "The bot likely lacks Manage Chat permission in %s.",
                    chat_id,
                    title
                )
                return False

            logging.exception(
                "Force-join Telegram API error for channel %s",
                chat_id
            )
            return False

        except Exception:
            logging.exception(
                "Force-join membership check failed for channel %s",
                chat_id
            )
            return False

    return True


async def force_join_configuration_error(user_id: int) -> str | None:
    """Return a configuration error message when a required channel cannot be checked."""
    channels = get_force_join_channels(enabled_only=True)

    for channel_id, chat_id, title, username, join_link, enabled in channels:
        try:
            await bot.get_chat_member(
                chat_id=chat_id,
                user_id=user_id
            )
        except TelegramBadRequest as exc:
            err = str(exc).lower()
            if "member list is inaccessible" in err:
                return (
                    f"<b>Force Join configuration error</b>\n\n"
                    f"Channel: <b>{html.escape(str(title))}</b>\n"
                    f"Chat ID: <code>{html.escape(str(chat_id))}</code>\n\n"
                    "Telegram is refusing the member lookup because this bot "
                    "cannot access the channel's member information.\n\n"
                    "<b>Fix:</b> make the bot an administrator of the channel "
                    "and grant it <b>Manage Chat</b> permission, then try again."
                )
            return None
        except Exception:
            return None

    return None


def get_force_join_keyboard():
    rows = []

    for channel_id, chat_id, title, username, join_link, enabled in get_force_join_channels(True):
        link = join_link or (
            f"https://t.me/{username}" if username else ""
        )
        if link:
            rows.append([
                InlineKeyboardButton(
                    text=f"Join {str(title)[:50]}",
                    url=link,
                    style="primary"
                )
            ])

    rows.append([
        InlineKeyboardButton(
            text="I Joined — Check Membership",
            callback_data="force_join_check",
            style="success"
        )
    ])

    return InlineKeyboardMarkup(inline_keyboard=rows)


async def send_force_join_prompt(user_id: int):
    channels = get_force_join_channels(True)
    if not channels:
        return

    try:
        chat = await bot.get_chat(user_id)
        username = getattr(chat, "username", None)
        first_name = getattr(chat, "first_name", None) or "there"
    except Exception:
        username = None
        first_name = "there"

    if username:
        greeting = f"@{html.escape(str(username))}"
    else:
        greeting = html.escape(str(first_name))

    lines = [
        "<tg-emoji emoji-id='5247133031235329609'>👋</tg-emoji> "
        f"<b>Hey {greeting}, Welcome to @agedcounterbot !</b>",
        "",
        "<i>Please join our main channel below</i>",
        "",
        "<tg-emoji emoji-id='5839473742215911858'>📢</tg-emoji> "
        "<b>Main Channel</b>"
    ]

    # Keep all enabled channels in the join keyboard, while the visible copy
    # stays aligned with the requested main-channel wording.
    if len(channels) > 1:
        lines.append("")
        lines.append("<i>Join all required channels to continue.</i>")

    await bot.send_message(
        chat_id=user_id,
        text="\n".join(lines),
        parse_mode="HTML",
        reply_markup=get_force_join_keyboard()
    )


async def show_force_join_for_callback(callback: types.CallbackQuery):
    channels = get_force_join_channels(True)
    if not channels:
        return

    user = callback.from_user
    username = getattr(user, "username", None)
    first_name = getattr(user, "first_name", None) or "there"

    if username:
        greeting = f"@{html.escape(str(username))}"
    else:
        greeting = html.escape(str(first_name))

    lines = [
        "<tg-emoji emoji-id='5247133031235329609'>👋</tg-emoji> "
        f"<b>Hey {greeting}, Welcome to @agedcounterbot !</b>",
        "",
        "<i>Please join our main channel below</i>",
        "",
        "<tg-emoji emoji-id='5839473742215911858'>📢</tg-emoji> "
        "<b>Main Channel</b>"
    ]

    if len(channels) > 1:
        lines.extend([
            "",
            "<i>Join all required channels to continue.</i>"
        ])

    await safe_edit(
        callback,
        "\n".join(lines),
        reply_markup=get_force_join_keyboard()
    )


@dp.callback_query(F.data == "force_join_check")
async def cb_force_join_check(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()

    if not await user_has_joined_required_channels(callback.from_user.id):
        config_error = await force_join_configuration_error(callback.from_user.id)
        if config_error:
            await safe_edit(
                callback,
                config_error,
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="Try Again",
                        callback_data="force_join_check",
                        style="primary"
                    )
                ],[
                    InlineKeyboardButton(
                        text="Main Menu",
                        callback_data="main_menu",
                        style="danger",
                        icon_custom_emoji_id=BACK_EMOJI_ID
                    )
                ]])
            )
            return

        await show_force_join_for_callback(callback)
        return

    await state.clear()

    await safe_edit(
        callback,
        get_welcome_text(),
        reply_markup=get_main_menu(callback.from_user.id)
    )


# --- ADMIN FORCE JOIN MANAGEMENT ---
@dp.callback_query(F.data == "admin_force_join")
async def cb_admin_force_join(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    channels = get_force_join_channels(False)

    lines = [
        "<tg-emoji emoji-id='6039641775377748623'>🔒</tg-emoji> "
        "<b>Force Join Channels</b>",
        "",
        "<i>Users must join every enabled channel before using the bot.</i>",
        ""
    ]
    rows = []

    for channel_id, chat_id, title, username, join_link, enabled in channels:
        status = "ON" if enabled else "OFF"
        lines.append(
            f"• <b>{html.escape(str(title))}</b> — <b>{status}</b>\n"
            f"<code>{html.escape(str(chat_id))}</code>"
        )
        rows.append([
            InlineKeyboardButton(
                text=("Disable " if enabled else "Enable ") + str(title)[:20],
                callback_data=f"admin_fj_toggle_{channel_id}",
                style="danger" if enabled else "success"
            ),
            InlineKeyboardButton(
                text="Delete",
                callback_data=f"admin_fj_delete_{channel_id}",
                style="danger"
            )
        ])

    if not channels:
        lines.append("<i>No channels configured.</i>")

    rows.append([
        InlineKeyboardButton(
            text="Add Channel",
            callback_data="admin_fj_add",
            style="success"
        )
    ])
    rows.append([
        InlineKeyboardButton(
            text="Check Channel Access",
            callback_data="admin_fj_test",
            style="primary"
        )
    ])
    rows.append([
        InlineKeyboardButton(
            text="Back to Admin Panel",
            callback_data="admin_panel",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )



@dp.callback_query(F.data == "admin_fj_test")
async def cb_admin_fj_test(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    channels = get_force_join_channels(enabled_only=True)
    if not channels:
        await callback.answer("No enabled force-join channels configured.", show_alert=True)
        return

    me = await bot.get_me()
    problems = []
    checked = 0

    for channel_id, chat_id, title, username, join_link, enabled in channels:
        try:
            member = await bot.get_chat_member(
                chat_id=chat_id,
                user_id=me.id
            )
            status = str(getattr(member, "status", "")).lower()

            if status not in {"administrator", "creator"}:
                problems.append(
                    f"• <b>{html.escape(str(title))}</b>: bot is not an administrator."
                )
                continue

            # Official Bot API documentation notes that can_manage_chat includes
            # the ability to see hidden supergroup/channel members.
            if not bool(getattr(member, "can_manage_chat", False)) and status != "creator":
                problems.append(
                    f"• <b>{html.escape(str(title))}</b>: "
                    "<b>Manage Chat</b> permission is missing."
                )
                continue

            checked += 1

        except TelegramBadRequest as exc:
            err = str(exc)
            if "member list is inaccessible" in err.lower():
                problems.append(
                    f"• <b>{html.escape(str(title))}</b>: member lookup is inaccessible. "
                    "Grant <b>Manage Chat</b>."
                )
            else:
                problems.append(
                    f"• <b>{html.escape(str(title))}</b>: "
                    f"<code>{html.escape(err)}</code>"
                )
        except Exception as exc:
            problems.append(
                f"• <b>{html.escape(str(title))}</b>: "
                f"<code>{html.escape(str(exc))}</code>"
            )

    await callback.answer(
        "Channel access looks good." if not problems else "Channel access needs attention.",
        show_alert=True
    )

    if problems:
        body = (
            "<b>Force Join Access Check</b>\n\n"
            + "\n".join(problems)
            + "\n\n"
            "<i>For membership verification, the bot should be an administrator "
            "with Manage Chat permission in each required channel.</i>"
        )
    else:
        body = (
            "<b>Force Join Access Check</b>\n\n"
            f"✅ Checked <b>{checked}</b> enabled channel(s).\n"
            "✅ The bot has the required administrative access."
        )

    await safe_edit(
        callback,
        body,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Back to Force Join",
                callback_data="admin_force_join",
                style="primary",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )


@dp.callback_query(F.data == "admin_fj_add")
async def cb_admin_fj_add(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_force_join_channel,
        "<b>Add Force-Join Channel</b>\n\n"
        "Send:\n"
        "<code>CHANNEL | JOIN_LINK</code>\n\n"
        "Example:\n"
        "<code>@mychannel | https://t.me/mychannel</code>\n\n"
        "The bot must be an administrator in the channel."
    )


@dp.message(AdminState.waiting_for_force_join_channel, F.text)
async def admin_force_join_input(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)
    parts = [p.strip() for p in (message.text or "").split("|", 1)]

    if len(parts) != 2:
        await message.answer(
            "❌ Use:\n<code>CHANNEL | JOIN_LINK</code>",
            parse_mode="HTML"
        )
        return

    channel_ref, join_link = parts

    if re.fullmatch(r"-?\d{5,20}", channel_ref):
        lookup = channel_ref
    elif re.fullmatch(r"@[A-Za-z0-9_]{5,32}", channel_ref):
        lookup = channel_ref
    else:
        await message.answer(
            "❌ Channel must be a numeric Chat ID or public @username.",
            parse_mode="HTML"
        )
        return

    if not re.fullmatch(
        r"https?://t\.me/(?:\+)?[A-Za-z0-9_+\-/]{3,120}",
        join_link
    ):
        await message.answer(
            "❌ Invalid JOIN_LINK.",
            parse_mode="HTML"
        )
        return

    try:
        chat = await bot.get_chat(lookup)
        me = await bot.get_me()
        bot_member = await bot.get_chat_member(
            chat_id=chat.id,
            user_id=me.id
        )
        bot_status = str(getattr(bot_member, "status", "")).lower()

        if bot_status not in {"administrator", "creator"}:
            await finish_admin_input(
                state,
                "❌ <b>Bot is not an administrator.</b>\n\n"
                f"Channel: <b>{html.escape(str(chat.title or lookup))}</b>\n\n"
                "Add the bot as an administrator and try again.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="Force Join",
                        callback_data="admin_force_join",
                        style="primary"
                    )
                ]])
            )
            return

        resolved_id = str(chat.id)
        title = str(chat.title or getattr(chat, "username", None) or resolved_id)
        username = getattr(chat, "username", None)
        force_id = f"FJ-{int(datetime.now().timestamp() * 1000)}"

        conn = sqlite3.connect("bot.db", timeout=30)
        try:
            conn.execute(
                "INSERT INTO force_join_channels "
                "(id,chat_id,title,username,join_link,enabled) "
                "VALUES(?,?,?,?,?,1)",
                (
                    force_id,
                    resolved_id,
                    title,
                    username,
                    join_link
                )
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            await finish_admin_input(
                state,
                "❌ <b>Channel already exists.</b>\n\n"
                f"<code>{html.escape(resolved_id)}</code>",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="Force Join",
                        callback_data="admin_force_join",
                        style="primary"
                    )
                ]])
            )
            return
        finally:
            conn.close()

        await finish_admin_input(
            state,
            "✅ <b>Force-Join Channel Added</b>\n\n"
            f"Channel: <b>{html.escape(title)}</b>\n"
            f"Chat ID: <code>{html.escape(resolved_id)}</code>\n"
            f"Join Link: <b>{html.escape(join_link)}</b>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Force Join",
                    callback_data="admin_force_join",
                    style="primary"
                )
            ]])
        )

    except Exception as exc:
        logging.exception("Force-join channel setup failed")
        await finish_admin_input(
            state,
            "❌ <b>Could not configure channel.</b>\n\n"
            f"<code>{html.escape(str(exc))}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Try Again",
                    callback_data="admin_fj_add",
                    style="primary"
                )
            ]])
        )


@dp.callback_query(F.data.startswith("admin_fj_toggle_"))
async def cb_admin_fj_toggle(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    channel_id = callback.data.replace("admin_fj_toggle_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT enabled,title FROM force_join_channels WHERE id=?",
            (channel_id,)
        ).fetchone()

        if not row:
            await callback.answer("Channel not found.", show_alert=True)
            return

        new_enabled = 0 if int(row[0]) else 1
        conn.execute(
            "UPDATE force_join_channels SET enabled=? WHERE id=?",
            (new_enabled, channel_id)
        )
        conn.commit()
        title = row[1]
    finally:
        conn.close()

    await callback.answer(
        f"{title}: {'enabled' if new_enabled else 'disabled'}."
    )
    await cb_admin_force_join(callback)


@dp.callback_query(F.data.startswith("admin_fj_delete_"))
async def cb_admin_fj_delete(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    channel_id = callback.data.replace("admin_fj_delete_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT title FROM force_join_channels WHERE id=?",
            (channel_id,)
        ).fetchone()

        if not row:
            await callback.answer("Channel not found.", show_alert=True)
            return

        conn.execute(
            "DELETE FROM force_join_channels WHERE id=?",
            (channel_id,)
        )
        conn.commit()
        title = row[0]
    finally:
        conn.close()

    await callback.answer(f"{title} removed.")
    await cb_admin_force_join(callback)


@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    await state.clear()

    if not is_admin(message.from_user.id):
        if not await user_has_joined_required_channels(message.from_user.id):
            await send_force_join_prompt(message.from_user.id)
            return
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (telegram_id, username) VALUES (?, ?)", 
                   (str(message.from_user.id), message.from_user.username or "user"))
    conn.commit()
    conn.close()

    welcome_text = get_welcome_text()
    image_path = "images/dash.png"
    main_menu = get_main_menu(message.from_user.id)
    if os.path.exists(image_path):
        photo = FSInputFile(image_path)
        await message.answer_photo(photo=photo, caption=welcome_text, parse_mode="HTML", reply_markup=main_menu)
    else:
        await message.answer(welcome_text, parse_mode="HTML", reply_markup=main_menu)

# --- WALLET & CRYPTO DEPOSIT SUBSYSTEM ---
@dp.message(Command("wallet"))
async def cmd_wallet(message: types.Message, state: FSMContext):
    await show_wallet_screen(message, user_id=message.from_user.id, state=state)

@dp.callback_query(F.data == "wallet")
async def cb_wallet(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    # Wallet is a safe navigation/escape route. Always cancel any unfinished
    # user task before opening the wallet.
    await state.clear()
    await show_wallet_screen(
        callback.message,
        user_id=callback.from_user.id,
        edit=True,
        callback=callback,
        state=None
    )

async def show_wallet_screen(msg_obj, user_id, edit=False, callback=None, state=None):
    if state:
        await state.clear()
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT balance, total_spent FROM users WHERE telegram_id = ?", (str(user_id),))
    row = cursor.fetchone()
    balance = row[0] if row and row[0] is not None else 0.0
    total_spent = row[1] if row and row[1] is not None else 0.0
    conn.close()

    text = (
        "<tg-emoji emoji-id='5893473283696759404'>💎</tg-emoji> "
        "<b>User Wallet</b>" + chr(10) + chr(10)
        + "<tg-emoji emoji-id='5224257782013769471'>💰</tg-emoji> "
        + f"<i>Available Balance: ${balance:.2f}</i>" + chr(10)
        + "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        + f"<i>Total Spent: ${total_spent:.2f}</i>" + chr(10) + chr(10)
        + "<b>Choose an option below</b>"
    )
    if edit and callback:
        await safe_edit(callback, text, reply_markup=get_wallet_menu())
    else:
        await msg_obj.answer(text, parse_mode="HTML", reply_markup=get_wallet_menu())


@dp.callback_query(F.data == "add_balance")
async def cb_add_balance(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    # Restart only this user's deposit workflow. Other users are unaffected.
    await state.clear()
    await state.set_state(DepositState.waiting_for_amount)

    text = (
        "<tg-emoji emoji-id='5893473283696759404'>💎</tg-emoji> "
        "<b>Add Balance</b>" + chr(10) + chr(10)
        + "<i>Choose a quick amount below or enter your own custom amount.</i>"
        + chr(10) + chr(10)
        + "<b>Quick Deposit</b>"
    )

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="$5", callback_data="amt_5", style="primary", icon_custom_emoji_id="5224257782013769471"),
            InlineKeyboardButton(text="$15", callback_data="amt_15", style="primary", icon_custom_emoji_id="5224257782013769471"),
            InlineKeyboardButton(text="$50", callback_data="amt_50", style="primary", icon_custom_emoji_id="5224257782013769471")
        ],
        [
            InlineKeyboardButton(text="Custom Amount", callback_data="custom_amount", style="primary", icon_custom_emoji_id="6039641775377748623")
        ],
        [
            InlineKeyboardButton(text="Cancel", callback_data="wallet", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)
        ]
    ])
    await safe_edit(callback, text, reply_markup=kb)



@dp.callback_query(F.data == "custom_amount")
async def cb_custom_amount(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    await state.set_state(DepositState.waiting_for_amount)

    text = (
        "<tg-emoji emoji-id='5893224751119208859'>💎</tg-emoji> "
        "<b>Enter Custom Amount</b>" + chr(10) + chr(10)
        + "<i>Send the amount as a number only.</i>" + chr(10) + chr(10)
        + "<tg-emoji emoji-id='5224257782013769471'>💵</tg-emoji> "
        "<b>Example:</b> <code>6</code>" + chr(10) + chr(10)
        + f"<i>Minimum: ${MIN_DEPOSIT:.0f} • Maximum: ${MAX_DEPOSIT:.0f}</i>"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="Cancel",
                callback_data="wallet",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]
    ])

    await safe_edit(
        callback,
        text,
        reply_markup=kb
    )



@dp.callback_query(F.data.startswith("amt_"))
async def cb_quick_amount(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    amt_str = callback.data.replace("amt_", "")
    await process_amount(callback.message, float(amt_str), callback.from_user, state)


@dp.message(DepositState.waiting_for_amount, F.text)
async def msg_amount_input(message: types.Message, state: FSMContext):
    raw = (message.text or "").strip()

    # Accept 6, 6.5, 6.50, 6$, 6.5$, 6.50$.
    # This intentionally does not use the `re` module.
    normalized = raw[:-1].strip() if raw.endswith("$") else raw

    try:
        if not normalized or normalized.count(".") > 1:
            raise ValueError

        if any(ch not in "0123456789." for ch in normalized):
            raise ValueError

        amt = float(normalized)

        if amt != amt or amt in (float("inf"), float("-inf")):
            raise ValueError

    except (TypeError, ValueError):
        await message.answer(
            "<tg-emoji emoji-id='5893224751119208859'>⚠️</tg-emoji> "
            "<b>Invalid Amount</b>\n\n"
            "Send only the amount.\n"
            "Example: <code>6</code>",
            parse_mode="HTML"
        )
        return

    if amt < MIN_DEPOSIT:
        await message.answer(
            "<tg-emoji emoji-id='5893224751119208859'>⚠️</tg-emoji> "
            f"<b>Minimum Amount: ${MIN_DEPOSIT:.0f}</b>",
            parse_mode="HTML"
        )
        return

    if amt > MAX_DEPOSIT:
        await message.answer(
            "<tg-emoji emoji-id='5893224751119208859'>⚠️</tg-emoji> "
            f"<b>Maximum Amount: ${MAX_DEPOSIT:.0f}</b>",
            parse_mode="HTML"
        )
        return

    await process_amount(message, amt, message.from_user, state)



async def process_amount(msg_obj, amount: float, user_obj, state: FSMContext):
    await state.update_data(deposit_amount=amount)

    text = (
        "<tg-emoji emoji-id='5893224751119208859'>💎</tg-emoji> "
        "<b>Select Crypto Currency</b>\n\n"
        "<tg-emoji emoji-id='6039641775377748623'>✨</tg-emoji> "
        f"<b>Amount: ${amount:.2f}</b>\n\n"
        "<i>Choose the cryptocurrency / network you want to pay with.</i>"
    )

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="USDT • BEP20", callback_data="crypto_USDT_BEP20", style="primary"),
            InlineKeyboardButton(text="USDT • TRC20", callback_data="crypto_USDT_TRC20", style="primary")
        ],
        [
            InlineKeyboardButton(text="USDT • ERC20", callback_data="crypto_USDT_ERC20", style="primary"),
            InlineKeyboardButton(text="USDC • ERC20", callback_data="crypto_USDC_ERC20", style="primary")
        ],
        [
            InlineKeyboardButton(text="BTC", callback_data="crypto_BTC", style="primary"),
            InlineKeyboardButton(text="ETH", callback_data="crypto_ETH", style="primary"),
            InlineKeyboardButton(text="SOL", callback_data="crypto_SOL", style="primary")
        ],
        [
            InlineKeyboardButton(text="Back to Wallet", callback_data="wallet", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)
        ]
    ])

    await msg_obj.answer(text, parse_mode="HTML", reply_markup=kb)



@dp.callback_query(F.data.startswith("crypto_"))
async def cb_select_crypto(callback: types.CallbackQuery, state: FSMContext):
    network = callback.data.replace("crypto_", "", 1)
    address = CRYPTO_ADDRESSES.get(network, "")
    if not address:
        await callback.answer("This network is not configured.", show_alert=True)
        return

    minimum, maximum, max_pending, enabled = get_payment_method(network)
    if not enabled:
        await callback.answer("This payment method is temporarily disabled.", show_alert=True)
        return

    data = await state.get_data()
    amount = data.get("deposit_amount")
    if amount is None:
        await callback.answer("Payment session expired. Start Add Balance again.", show_alert=True)
        await state.clear()
        return

    amount=float(amount)
    if amount < minimum or amount > maximum:
        await callback.answer(
            f"Allowed amount: ${minimum:.2f} - ${maximum:.2f}",
            show_alert=True
        )
        return

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        pending=conn.execute(
            "SELECT COUNT(*) FROM deposits WHERE telegram_id=? AND status='pending' AND screenshot_url IS NOT NULL",
            (str(callback.from_user.id),)
        ).fetchone()[0]
    finally:
        conn.close()

    if pending >= int(max_pending):
        await callback.answer(
            "You already have the maximum number of pending payments.",
            show_alert=True
        )
        return

    await state.update_data(crypto_network=network)
    await callback.answer()

    text=(
        "<tg-emoji emoji-id='5224257782013769471'>💳</tg-emoji> "
        "<b>Crypto Payment Details</b>"+chr(10)+chr(10)
        +f"Amount: <b>${amount:.2f}</b>"+chr(10)
        +f"Network: <b>{network.replace('_',' ')}</b>"+chr(10)+chr(10)
        +"<b>Send payment to:</b>"+chr(10)
        +f"<code>{address}</code>"+chr(10)+chr(10)
        +"<i>Use the selected network only and send the exact amount.</i>"+chr(10)+chr(10)
        +"<b>After sending, tap Payment Sent — Done.</b>"
    )
    kb=InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Payment Sent — Done",callback_data="payment_sent_done",
                              style="primary")],
        [InlineKeyboardButton(text="Cancel",callback_data="wallet",
                              style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)]
    ])
    await safe_edit(callback,text,reply_markup=kb)


@dp.callback_query(F.data == "payment_sent_done")
async def cb_payment_sent_done(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    if not data.get("deposit_amount") or not data.get("crypto_network"):
        await callback.answer("Payment session expired. Start again.", show_alert=True)
        await state.clear()
        return

    await callback.answer()
    await state.set_state(DepositState.waiting_for_txhash)

    await callback.message.answer(
        "<tg-emoji emoji-id='5893224751119208859'>🔗</tg-emoji> "
        "<b>Transaction ID Required</b>" + chr(10) + chr(10)
        + "<i>Send the transaction hash / TXID for the payment.</i>" + chr(10) + chr(10)
        + "<b>Send TXID only.</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Cancel", callback_data="wallet",
                                  style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    )


@dp.message(DepositState.waiting_for_txhash, F.text)
async def msg_txhash_input(message: types.Message, state: FSMContext):
    tx_hash = (message.text or "").strip()

    if not tx_hash or len(tx_hash) < 8 or len(tx_hash) > 200:
        await message.answer(
            "<tg-emoji emoji-id='5893224751119208859'>⚠️</tg-emoji> "
            "<b>Invalid TXID</b>" + chr(10) + chr(10)
            + "Send the complete transaction hash / TXID.",
            parse_mode="HTML"
        )
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM deposits WHERE txn_id=?", (tx_hash,))
    exists = cursor.fetchone()
    conn.close()

    if exists:
        await message.answer("<b>This TXID has already been submitted.</b>", parse_mode="HTML")
        return

    await state.update_data(tx_hash=tx_hash)
    await state.set_state(DepositState.waiting_for_proof)

    await message.answer(
        "<tg-emoji emoji-id='5224257782013769471'>📸</tg-emoji> "
        "<b>Payment Screenshot Required</b>" + chr(10) + chr(10)
        + "<i>Upload a clear screenshot showing the completed transaction.</i>" + chr(10) + chr(10)
        + "After the screenshot is received, your payment will be sent to admin review.",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Cancel", callback_data="wallet",
                                  style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    )


@dp.message(DepositState.waiting_for_proof, F.photo | F.document)
async def msg_proof_photo_input(message: types.Message, state: FSMContext):
    if message.photo:
        proof_file_id = message.photo[-1].file_id
    elif message.document:
        # Telegram documents can contain screenshots too.
        mime = (message.document.mime_type or "").lower()
        if mime and not mime.startswith("image/"):
            await message.answer(
                "<b>Please upload an image screenshot.</b>",
                parse_mode="HTML"
            )
            return
        proof_file_id = message.document.file_id
    else:
        await message.answer("Please upload the payment screenshot.")
        return

    data = await state.get_data()
    tx_hash = data.get("tx_hash")

    if not tx_hash:
        await state.clear()
        await message.answer("Payment session expired. Start Add Balance again.")
        return

    await create_pending_deposit(message, state, tx_hash, proof_file_id)


@dp.message(DepositState.waiting_for_proof)
async def msg_proof_invalid_input(message: types.Message, state: FSMContext):
    await message.answer(
        "<b>Screenshot required.</b>" + chr(10) + chr(10)
        + "Please upload the payment screenshot as an image.",
        parse_mode="HTML"
    )


async def create_pending_deposit(message: types.Message, state: FSMContext, tx_hash: str, proof_file_id: str):
    data = await state.get_data()
    amount = data.get("deposit_amount")
    network = data.get("crypto_network")

    if amount is None or not network:
        await state.clear()
        await message.answer("Payment session expired. Please start Add Balance again.")
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM deposits WHERE txn_id=?", (tx_hash,))
    if cursor.fetchone():
        conn.close()
        await message.answer("This transaction hash has already been submitted.")
        return

    dep_id = f"DEP-{int(datetime.now().timestamp()*1000)}"
    try:
        cursor.execute("""
            INSERT INTO deposits
            (id, telegram_id, username, amount, txn_id, screenshot_url, status, crypto_network)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (
            dep_id, str(message.from_user.id), message.from_user.username or "user",
            float(amount), tx_hash, proof_file_id, network
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        await message.answer("This transaction hash has already been submitted.")
        return
    finally:
        conn.close()

    await state.clear()

    await message.answer(
        "<tg-emoji emoji-id='6039641775377748623'>⏳</tg-emoji> "
        "<b>Payment Submitted Successfully</b>" + chr(10) + chr(10)
        + f"Request ID: <code>{dep_id}</code>" + chr(10)
        + f"Amount: <b>${float(amount):.2f}</b>" + chr(10)
        + f"Network: <b>{network.replace('_', ' ')}</b>" + chr(10)
        + f"TXID: <code>{tx_hash}</code>" + chr(10) + chr(10)
        + "<b>Status: Under Admin Review</b>" + chr(10) + chr(10)
        + "Please allow approximately <b>5–20 minutes</b> for verification." + chr(10)
        + "Your balance will be added after the payment is verified.",
        parse_mode="HTML",
        reply_markup=get_wallet_menu()
    )

    admin_text = (
        "<tg-emoji emoji-id='5224257782013769471'>💳</tg-emoji> "
        "<b>NEW PAYMENT — REVIEW REQUIRED</b>" + chr(10) + chr(10)
        + f"Request ID: <code>{dep_id}</code>" + chr(10)
        + f"User: @{message.from_user.username or 'user'}" + chr(10)
        + f"Telegram ID: <code>{message.from_user.id}</code>" + chr(10)
        + f"Amount: <b>${float(amount):.2f}</b>" + chr(10)
        + f"Network: <b>{network.replace('_', ' ')}</b>" + chr(10)
        + f"TXID: <code>{tx_hash}</code>" + chr(10)
        + "<b>Status: PENDING</b>" + chr(10) + chr(10)
        + "<i>Verify the transaction and screenshot before approving.</i>"
    )

    admin_kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(
            text=f"Approve {dep_id}",
            callback_data=f"adm_appr_{dep_id}",
            style="primary"
        ),
        InlineKeyboardButton(
            text=f"Reject {dep_id}",
            callback_data=f"adm_rej_{dep_id}",
            style="danger"
        )
    ]])

    try:
        # Telegram accepts photo file_ids through send_photo, while screenshots
        # uploaded as documents must be forwarded with send_document.
        review_chat = (
            get_payment_setting("review_group_chat_id", "").strip()
            or str(ADMIN_TELEGRAM_ID)
        )
        if message.photo:
            await bot.send_photo(
                chat_id=review_chat,
                photo=proof_file_id,
                caption=admin_text,
                parse_mode="HTML",
                reply_markup=admin_kb
            )
        else:
            await bot.send_document(
                chat_id=review_chat,
                document=proof_file_id,
                caption=admin_text,
                parse_mode="HTML",
                reply_markup=admin_kb
            )
    except Exception:
        logging.exception("Admin payment notification failed")
        # Do not tell the user the payment was successfully queued if the
        # admin notification itself failed.
        try:
            await bot.send_message(
                chat_id=message.from_user.id,
                text=(
                    "<b>Payment received, but admin notification failed.</b>" + chr(10) + chr(10)
                    + f"Request ID: <code>{dep_id}</code>" + chr(10)
                    + "Please contact support with this Request ID."
                ),
                parse_mode="HTML"
            )
        except Exception:
            logging.exception("Payment notification failure message failed")


# --- BALANCE HISTORY HANDLER ---
@dp.callback_query(F.data.startswith("balance_history_"))
async def cb_balance_history(callback: types.CallbackQuery):
    await callback.answer()
    raw_page = callback.data.replace("balance_history_", "", 1)
    try:
        page=max(1,int(raw_page or 1))
    except ValueError:
        page=1

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS wallet_transactions (
            id TEXT PRIMARY KEY,
            telegram_id TEXT,
            type TEXT,
            title TEXT,
            amount REAL,
            balance_before REAL,
            balance_after REAL,
            reference_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        per_page=5
        offset=(page-1)*per_page
        txns=conn.execute("""
            SELECT title, amount, balance_after, created_at, reference_id
            FROM wallet_transactions
            WHERE telegram_id=?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """,(str(callback.from_user.id),per_page,offset)).fetchall()
        total=conn.execute(
            "SELECT COUNT(*) FROM wallet_transactions WHERE telegram_id=?",
            (str(callback.from_user.id),)
        ).fetchone()[0]
        conn.commit()
    except sqlite3.Error:
        logging.exception("Balance history query failed")
        txns=[]; total=0
    finally:
        conn.close()

    if not txns:
        await safe_edit(
            callback,
            "<tg-emoji emoji-id='5895444149699612825'>📊</tg-emoji> "
            "<b>Balance History</b>"+chr(10)+chr(10)
            +"<i>No transactions recorded yet.</i>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="Back to Wallet",callback_data="wallet",
                                      style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)]
            ])
        )
        return

    lines=[
        f"<tg-emoji emoji-id='5895444149699612825'>📊</tg-emoji> "
        f"<b>Balance History</b> • Page {page}",""
    ]
    for title,amount,b_after,created,ref in txns:
        amount=float(amount or 0)
        lines.append(
            f"<b>{title}</b> • <code>{'+' if amount>0 else ''}${amount:.2f}</code>"
            +chr(10)
            +f"<i>{created} • Balance ${float(b_after or 0):.2f} • Ref: {ref or '-'}</i>"
        )
    nav=[]
    if page>1:
        nav.append(InlineKeyboardButton(text="Previous",callback_data=f"balance_history_{page-1}",style="primary"))
    if page*per_page<total:
        nav.append(InlineKeyboardButton(text="Next",callback_data=f"balance_history_{page+1}",style="primary"))
    rows=[nav] if nav else []
    rows.append([InlineKeyboardButton(text="Back to Wallet",callback_data="wallet",style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)])
    await safe_edit(callback,chr(10).join(lines),reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))


# --- PROMO CODES SUBSYSTEM ---
@dp.callback_query(F.data == "promocodes")
async def cb_promocodes(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    await state.set_state(PromoState.waiting_for_code)
    text = (
        "<tg-emoji emoji-id='5893376775781617954'>🎟️</tg-emoji> "
        "<b>Redeem Promo Code</b>" + chr(10) + chr(10)
        + "Please type and send your promo code below to claim bonus balance:"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Cancel", callback_data="wallet", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
    ])
    await safe_edit(callback, text, reply_markup=kb)



@dp.message(PromoState.waiting_for_code)
async def msg_promo_input(message: types.Message, state: FSMContext):
    code = message.text.strip().upper()
    user_id = str(message.from_user.id)

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT id, reward_type, reward_value, max_uses, used_count, per_user_limit, min_wallet_req, expires_at, is_active FROM promo_codes WHERE UPPER(code) = ?", (code,))
    promo = cursor.fetchone()

    if not promo or not promo[8]:
        conn.close()
        await message.answer("❌ Invalid or inactive promo code!")
        return

    p_id, r_type, r_val, max_u, u_cnt, u_lim, min_bal, exp, active = promo
    today = datetime.now().strftime("%Y-%m-%d")
    if exp and exp < today:
        conn.close()
        await message.answer("❌ This promo code has expired!")
        return
    if u_cnt >= max_u:
        conn.close()
        await message.answer("❌ Maximum usage limit reached for this promo code!")
        return

    # Check per user uses
    cursor.execute("SELECT COUNT(*) FROM promo_usages WHERE promo_id = ? AND telegram_id = ?", (p_id, user_id))
    user_uses = cursor.fetchone()[0]
    if user_uses >= u_lim:
        conn.close()
        await message.answer(f"❌ You have already redeemed this promo code (Limit: {u_lim} per user).")
        return

    # Check min balance
    cursor.execute("SELECT balance FROM users WHERE telegram_id = ?", (user_id,))
    u_row = cursor.fetchone()
    b_before = u_row[0] if u_row and u_row[0] is not None else 0.0
    if min_bal and b_before < min_bal:
        conn.close()
        await message.answer(f"❌ Minimum wallet balance requirement of ${min_bal:.2f} not met.")
        return

    reward = r_val if r_type == "fixed" else (b_before * r_val / 100.0)
    b_after = b_before + reward

    cursor.execute("UPDATE users SET balance = ? WHERE telegram_id = ?", (b_after, user_id))
    cursor.execute("UPDATE promo_codes SET used_count = used_count + 1 WHERE id = ?", (p_id,))
    pu_id = f"PU-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("INSERT INTO promo_usages (id, promo_id, code, telegram_id, reward_amount) VALUES (?, ?, ?, ?, ?)", (pu_id, p_id, code, user_id, reward))
    conn.commit()
    conn.close()

    await state.clear()
    log_transaction(user_id, "promo", "🎟️ Promo Reward", reward, b_before, b_after, code)

    await message.answer(
        f"🎉 <b>Promo Code Applied!</b>\n\n"
        f"Reward: <b>${reward:.2f}</b>\n"
        f"💰 New Balance: <b>${b_after:.2f}</b>",
        parse_mode="HTML",
        reply_markup=get_wallet_menu()
    )

# --- ADMIN DEPOSIT APPROVAL HANDLERS ---
@dp.callback_query(F.data.startswith("adm_appr_"))
async def cb_admin_approve_deposit(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized", show_alert=True)
        return

    dep_id = callback.data.replace("adm_appr_", "", 1)
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT telegram_id, amount, status FROM deposits WHERE id=?", (dep_id,))
        row = cursor.fetchone()

        if not row or row[2] != "pending":
            conn.rollback()
            conn.close()
            await callback.answer("Payment already processed or not found.", show_alert=True)
            return

        user_id, amount, _ = row
        cursor.execute("SELECT balance FROM users WHERE telegram_id=?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            conn.rollback()
            conn.close()
            await callback.answer("User not found.", show_alert=True)
            return

        before = float(user_row[0] or 0)
        after = before + float(amount)

        cursor.execute("UPDATE deposits SET status='approved' WHERE id=? AND status='pending'", (dep_id,))
        cursor.execute("UPDATE users SET balance=? WHERE telegram_id=?", (after, user_id))
        conn.commit()
        conn.close()

        log_transaction(user_id, "deposit", "Balance Added", float(amount), before, after, dep_id)

        await callback.answer(f"Approved +${float(amount):.2f}", show_alert=True)
        try:
            await callback.message.edit_reply_markup(reply_markup=None)
        except Exception:
            pass

        try:
            await bot.send_message(
                chat_id=int(user_id),
                text=(
                    "<tg-emoji emoji-id='6039641775377748623'>✓</tg-emoji> "
                    "<b>Payment Verified — Balance Added</b>" + chr(10) + chr(10)
                    + f"Request ID: <code>{dep_id}</code>" + chr(10)
                    + f"Amount Added: <b>${float(amount):.2f}</b>" + chr(10) + chr(10)
                    + "Your crypto payment has been verified by admin and the balance is now available in your wallet."
                ),
                parse_mode="HTML",
                reply_markup=get_wallet_menu()
            )
        except Exception:
            logging.exception("Approval notification failed")

    except Exception:
        conn.rollback()
        conn.close()
        logging.exception("Deposit approval failed")
        await callback.answer("Approval failed. Nothing was credited.", show_alert=True)


@dp.callback_query(F.data.startswith("adm_rej_"))
async def cb_admin_reject_deposit(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized", show_alert=True)
        return

    dep_id = callback.data.replace("adm_rej_", "", 1)
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT telegram_id, status FROM deposits WHERE id=?", (dep_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        await callback.answer("Payment not found.", show_alert=True)
        return

    user_id, status = row
    if status != "pending":
        conn.close()
        await callback.answer("Payment already processed.", show_alert=True)
        return

    cursor.execute("UPDATE deposits SET status='rejected' WHERE id=? AND status='pending'", (dep_id,))
    conn.commit()
    conn.close()

    await callback.answer(f"Payment {dep_id} rejected.", show_alert=True)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass

    try:
        await bot.send_message(
            chat_id=int(user_id),
            text=(
                "<tg-emoji emoji-id='5893224751119208859'>⚠️</tg-emoji> "
                "<b>Payment Rejected</b>" + chr(10) + chr(10)
                + f"Request ID: <code>{dep_id}</code>" + chr(10)
                + "The submitted payment could not be verified." + chr(10) + chr(10)
                + "If you believe this is an error, please contact support."
            ),
            parse_mode="HTML",
            reply_markup=get_wallet_menu()
        )
    except Exception:
        logging.exception("Rejection notification failed")


# --- COMMAND /ADMIN & ADMIN CALLBACKS ---

def is_owner(user_id):
    try:
        return int(user_id) == int(ADMIN_TELEGRAM_ID)
    except (TypeError, ValueError):
        return False


def admin_actor_key(user_id: int) -> str:
    """Stable per-admin key for ephemeral panel/input state."""
    return f"admin:{int(user_id)}"


def is_admin(user_id):
    try:
        uid = str(int(user_id))
    except (TypeError, ValueError):
        return False

    if uid == str(ADMIN_TELEGRAM_ID):
        return True

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        return bool(
            conn.execute(
                "SELECT 1 FROM admins WHERE telegram_id=?",
                (uid,)
            ).fetchone()
        )
    except sqlite3.Error:
        logging.exception("Admin lookup failed")
        return False
    finally:
        conn.close()


async def show_admin_panel(msg_obj, edit=False, callback=None):
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM deposits")
    payments = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM deposits WHERE status='pending'")
    pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM orders")
    orders = cursor.fetchone()[0]
    cursor.execute("SELECT COALESCE(SUM(amount),0) FROM deposits WHERE status='approved'")
    volume = cursor.fetchone()[0]
    conn.close()

    text = (
        "<tg-emoji emoji-id='5039539210072097557'>🛡️</tg-emoji> <b>Admin Control Center</b>"
        + chr(10) + chr(10)
        + "<i>Manage users, balances, payments, orders and broadcasts.</i>"
        + chr(10) + chr(10)
        + f"Users: <b>{users}</b>" + chr(10)
        + f"Payments: <b>{payments}</b>" + chr(10)
        + f"Pending Payments: <b>{pending}</b>" + chr(10)
        + f"Orders: <b>{orders}</b>" + chr(10)
        + f"Approved Volume: <b>${volume:.2f}</b>"
    )
    if edit and callback:
        await safe_edit(callback, text, reply_markup=get_admin_menu())
    else:
        await msg_obj.answer(text, parse_mode="HTML", reply_markup=get_admin_menu())


@dp.message(Command("admin"))
async def cmd_admin(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.answer("Unauthorized access. Admin only.")
        return
    await show_admin_panel(message)


@dp.callback_query(F.data == "admin_panel")
async def cb_admin_panel(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    await show_admin_panel(callback.message, edit=True, callback=callback)





# --- ADMIN ACCESS MANAGEMENT ---
@dp.callback_query(F.data == "admin_manage_admins")
async def cb_admin_manage_admins(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        await callback.answer(
            "Only the owner can manage administrators.",
            show_alert=True
        )
        return

    await callback.answer()
    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        admins = conn.execute(
            "SELECT telegram_id, role, added_by, added_at "
            "FROM admins ORDER BY CASE WHEN role='owner' THEN 0 ELSE 1 END, added_at ASC"
        ).fetchall()
    finally:
        conn.close()

    lines = [
        "<tg-emoji emoji-id='5039539210072097557'>🛡️</tg-emoji> "
        "<b>Admin Access</b>",
        "",
        "Owner and authorized administrators:",
        ""
    ]
    rows = []

    for uid, role, added_by, added_at in admins:
        role_label = "OWNER" if role == "owner" else "ADMIN"
        lines.append(
            f"• <code>{html.escape(str(uid))}</code> — <b>{role_label}</b>"
        )
        if role != "owner":
            rows.append([
                InlineKeyboardButton(
                    text=f"Remove {uid}",
                    callback_data=f"admin_remove_{uid}",
                    style="danger"
                )
            ])

    if not admins:
        lines.append("<i>No admin records found.</i>")

    rows.extend([
        [
            InlineKeyboardButton(
                text="Add Admin",
                callback_data="admin_add_admin",
                style="success"
            )
        ],
        [
            InlineKeyboardButton(
                text="Back to Admin Panel",
                callback_data="admin_panel",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]
    ])

    await safe_edit(
        callback,
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data == "admin_add_admin")
async def cb_admin_add_admin(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        await callback.answer(
            "Only the owner can add administrators.",
            show_alert=True
        )
        return

    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_admin_id,
        "<tg-emoji emoji-id='5033259521208747582'>👤</tg-emoji> "
        "<b>Add Administrator</b>\n\n"
        "Send the person's numeric Telegram Chat ID.\n\n"
        "Example:\n<code>123456789</code>"
    )


@dp.message(AdminState.waiting_for_admin_id, F.text)
async def admin_add_admin_input(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)
    raw = (message.text or "").strip()

    if not raw.isdigit():
        await message.answer(
            "❌ Send a numeric Telegram Chat ID only.",
            parse_mode="HTML"
        )
        return

    uid = str(int(raw))
    if uid == str(ADMIN_TELEGRAM_ID):
        await finish_admin_input(
            state,
            "ℹ️ <b>This user is already the owner.</b>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Back to Admin Access",
                    callback_data="admin_manage_admins",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]])
        )
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO admins (telegram_id, role, added_by) "
            "VALUES (?, 'admin', ?)",
            (uid, str(message.from_user.id))
        )
        conn.commit()
        created = conn.execute(
            "SELECT 1 FROM admins WHERE telegram_id=?",
            (uid,)
        ).fetchone()
    except sqlite3.Error:
        conn.rollback()
        logging.exception("Failed to add admin")
        await finish_admin_input(
            state,
            "❌ <b>Could not add administrator.</b>\n\nDatabase error.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Back to Admin Access",
                    callback_data="admin_manage_admins",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]])
        )
        return
    finally:
        conn.close()

    await finish_admin_input(
        state,
        "✅ <b>Administrator Added</b>\n\n"
        f"Chat ID: <code>{uid}</code>\n"
        f"Status: <b>{'Active' if created else 'Not Added'}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Manage Admins",
                    callback_data="admin_manage_admins",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Admin Panel",
                    callback_data="admin_panel",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("admin_remove_"))
async def cb_admin_remove_admin(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        await callback.answer(
            "Only the owner can manage administrators.",
            show_alert=True
        )
        return

    uid = callback.data.replace("admin_remove_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT role FROM admins WHERE telegram_id=?",
            (uid,)
        ).fetchone()

        if not row:
            await callback.answer("Administrator not found.", show_alert=True)
            return

        if row[0] == "owner" or uid == str(ADMIN_TELEGRAM_ID):
            await callback.answer(
                "The owner cannot be removed.",
                show_alert=True
            )
            return

        conn.execute("DELETE FROM admins WHERE telegram_id=?", (uid,))
        conn.commit()
    finally:
        conn.close()

    await callback.answer("Administrator removed.")
    await cb_admin_manage_admins(callback)


# --- CRYPTO PAYMENT SETTINGS ---
def _payment_method_label(network: str) -> str:
    return network.replace("_", " • ")


@dp.callback_query(F.data == "admin_crypto_settings")
async def cb_admin_crypto_settings(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    rows = []
    lines = [
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        "<b>Crypto Payment Settings</b>",
        "",
        "<i>Tap a network to edit its address, limits, pending limit or status.</i>",
        ""
    ]

    for network in CRYPTO_NETWORKS:
        minimum, maximum, max_pending, enabled = get_payment_method(network)
        address = get_bot_setting(
            f"crypto_{network}",
            CRYPTO_ADDRESSES.get(network, "")
        )
        status = "ON" if enabled else "OFF"
        address_state = "Configured" if address else "Not set"

        lines.append(
            f"<b>{html.escape(_payment_method_label(network))}</b> • "
            f"<b>{status}</b>\n"
            f"Address: <i>{address_state}</i> • "
            f"${minimum:.2f}–${maximum:.2f} • "
            f"Pending: {int(max_pending)}"
        )

        rows.append([
            InlineKeyboardButton(
                text=_payment_method_label(network),
                callback_data=f"admin_crypto_edit_{network}",
                style="primary"
            ),
            InlineKeyboardButton(
                text=("Disable" if enabled else "Enable"),
                callback_data=f"admin_crypto_toggle_{network}",
                style="danger" if enabled else "success"
            )
        ])

    rows.append([
        InlineKeyboardButton(
            text="Back to Admin Panel",
            callback_data="admin_panel",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data.startswith("admin_crypto_toggle_"))
async def cb_admin_crypto_toggle(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    network = callback.data.replace("admin_crypto_toggle_", "", 1)
    if network not in CRYPTO_NETWORKS:
        await callback.answer("Payment network not found.", show_alert=True)
        return

    minimum, maximum, max_pending, enabled = get_payment_method(network)
    set_payment_method(
        network,
        minimum,
        maximum,
        max_pending,
        0 if enabled else 1
    )

    await callback.answer(
        f"{_payment_method_label(network)} "
        f"{'enabled' if not enabled else 'disabled'}."
    )
    await cb_admin_crypto_settings(callback)


@dp.callback_query(F.data.startswith("admin_crypto_edit_"))
async def cb_admin_crypto_edit(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    network = callback.data.replace("admin_crypto_edit_", "", 1)
    if network not in CRYPTO_NETWORKS:
        await callback.answer("Payment network not found.", show_alert=True)
        return

    minimum, maximum, max_pending, enabled = get_payment_method(network)
    address = get_bot_setting(
        f"crypto_{network}",
        CRYPTO_ADDRESSES.get(network, "")
    )

    await callback.answer()

    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        f"<b>{html.escape(_payment_method_label(network))}</b>\n\n"
        f"Status: <b>{'Enabled' if enabled else 'Disabled'}</b>\n"
        f"Address: <code>{html.escape(address or 'Not configured')}</code>\n"
        f"Min: <b>${minimum:.2f}</b>\n"
        f"Max: <b>${maximum:.2f}</b>\n"
        f"Pending limit: <b>{int(max_pending)}</b>\n\n"
        "<i>Choose what to edit.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Edit Address",
                    callback_data=f"admin_crypto_addr_{network}",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Edit Limits",
                    callback_data=f"admin_crypto_limit_{network}",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text=("Disable" if enabled else "Enable"),
                    callback_data=f"admin_crypto_toggle_{network}",
                    style="danger" if enabled else "success"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Back",
                    callback_data="admin_crypto_settings",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("admin_crypto_addr_"))
async def cb_admin_crypto_address(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    network = callback.data.replace("admin_crypto_addr_", "", 1)
    if network not in CRYPTO_NETWORKS:
        await callback.answer("Payment network not found.", show_alert=True)
        return

    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_crypto_address,
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        f"<b>Edit {_payment_method_label(network)} Address</b>\n\n"
        "Send the new receiving address.\n"
        "The change is saved immediately."
    )
    await state.update_data(crypto_network=network)


@dp.message(AdminState.waiting_for_crypto_address, F.text)
async def admin_crypto_address_input(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)
    address = (message.text or "").strip()
    data = await state.get_data()
    network = data.get("crypto_network")

    if network not in CRYPTO_NETWORKS:
        await finish_admin_input(
            state,
            "❌ <b>Payment network not found.</b>",
            reply_markup=get_admin_menu()
        )
        return

    if len(address) < 6 or len(address) > 256 or any(ch.isspace() for ch in address):
        await message.answer(
            "❌ <b>Invalid address.</b>\n\n"
            "Send the wallet address as one line without spaces.",
            parse_mode="HTML"
        )
        return

    set_bot_setting(f"crypto_{network}", address)
    CRYPTO_ADDRESSES[network] = address

    await finish_admin_input(
        state,
        "✅ <b>Crypto Address Updated</b>\n\n"
        f"Network: <b>{html.escape(_payment_method_label(network))}</b>\n"
        f"Address: <code>{html.escape(address)}</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Crypto Settings",
                    callback_data="admin_crypto_settings",
                    style="primary"
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("admin_crypto_limit_"))
async def cb_admin_crypto_limits(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    network = callback.data.replace("admin_crypto_limit_", "", 1)
    if network not in CRYPTO_NETWORKS:
        await callback.answer("Payment network not found.", show_alert=True)
        return

    minimum, maximum, max_pending, enabled = get_payment_method(network)

    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_payment_method_settings,
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        f"<b>Edit {_payment_method_label(network)} Limits</b>\n\n"
        "Send:\n"
        "<code>MIN | MAX | PENDING</code>\n\n"
        f"Current: <code>{minimum} | {maximum} | {max_pending}</code>\n\n"
        "Example: <code>5 | 5000 | 2</code>"
    )
    await state.update_data(crypto_network=network)


@dp.message(AdminState.waiting_for_payment_method_settings, F.text)
async def admin_payment_method_settings_input(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)
    parts = [p.strip() for p in (message.text or "").split("|")]
    data = await state.get_data()
    network = data.get("crypto_network")

    if network not in CRYPTO_NETWORKS:
        await finish_admin_input(
            state,
            "❌ <b>Payment network not found.</b>",
            reply_markup=get_admin_menu()
        )
        return

    if len(parts) != 3:
        await message.answer(
            "❌ Use exactly:\n<code>MIN | MAX | PENDING</code>",
            parse_mode="HTML"
        )
        return

    try:
        minimum = float(parts[0])
        maximum = float(parts[1])
        pending = int(parts[2])

        if minimum <= 0 or maximum <= minimum or pending <= 0:
            raise ValueError

    except ValueError:
        await message.answer(
            "❌ <b>Invalid limits.</b>\n\n"
            "MIN and MAX must be positive, MAX must be greater than MIN, "
            "and PENDING must be a positive integer.",
            parse_mode="HTML"
        )
        return

    _, _, _, enabled = get_payment_method(network)
    set_payment_method(network, minimum, maximum, pending, enabled)

    await finish_admin_input(
        state,
        "✅ <b>Payment Limits Updated</b>\n\n"
        f"Network: <b>{html.escape(_payment_method_label(network))}</b>\n"
        f"Minimum: <b>${minimum:.2f}</b>\n"
        f"Maximum: <b>${maximum:.2f}</b>\n"
        f"Pending limit: <b>{pending}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Crypto Settings",
                    callback_data="admin_crypto_settings",
                    style="primary"
                )
            ]
        ])
    )




# --- PAYMENT REVIEW CHANNEL ---
@dp.callback_query(F.data == "admin_payment_channel")
async def cb_admin_payment_channel(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()

    chat_id = get_payment_setting("review_group_chat_id", "").strip()
    channel_link = get_payment_setting("review_group_link", "").strip()

    if chat_id:
        status_text = (
            f"<b>Configured Chat ID:</b> <code>{html.escape(chat_id)}</code>\n"
            f"<b>Link:</b> <b>{html.escape(channel_link or 'Not set')}</b>\n\n"
            "<i>New deposit/payment reviews are sent here for admin approval.</i>"
        )
    else:
        status_text = (
            "<i>No payment review channel is configured.</i>\n\n"
            "<i>Until one is configured, payment review messages fall back "
            "to the owner account.</i>"
        )

    rows = [
        [
            InlineKeyboardButton(
                text="Set / Edit Channel",
                callback_data="admin_payment_channel_edit",
                style="primary"
            )
        ]
    ]

    if chat_id:
        rows.append([
            InlineKeyboardButton(
                text="Clear Channel",
                callback_data="admin_payment_channel_clear",
                style="danger"
            )
        ])

    rows.append([
        InlineKeyboardButton(
            text="Back to Admin Panel",
            callback_data="admin_panel",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        "<b>Payment Review Channel</b>\n\n"
        + status_text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data == "admin_payment_channel_edit")
async def cb_admin_payment_channel_edit(
    callback: types.CallbackQuery,
    state: FSMContext
):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()

    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_payment_review_channel,
        "<tg-emoji emoji-id='5893473283696759404'>💳</tg-emoji> "
        "<b>Set Payment Review Channel</b>\n\n"
        "Send:\n"
        "<code>CHAT_ID | CHANNEL_LINK</code>\n\n"
        "Examples:\n"
        "<code>-1001234567890 | https://t.me/yourchannel</code>\n"
        "<code>@yourchannel | https://t.me/yourchannel</code>\n\n"
        "The bot must be an administrator of the destination."
    )


@dp.message(AdminState.waiting_for_payment_review_channel, F.text)
async def admin_payment_review_channel_input(
    message: types.Message,
    state: FSMContext
):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)

    parts = [p.strip() for p in (message.text or "").split("|", 1)]
    if len(parts) != 2:
        await message.answer(
            "❌ Use:\n<code>CHAT_ID | CHANNEL_LINK</code>",
            parse_mode="HTML"
        )
        return

    chat_ref, channel_link = parts

    if re.fullmatch(r"-?\d{5,20}", chat_ref):
        lookup = chat_ref
    elif re.fullmatch(r"@[A-Za-z0-9_]{5,32}", chat_ref):
        lookup = chat_ref
    else:
        await message.answer(
            "❌ CHAT_ID must be a numeric Telegram chat ID or public @username.",
            parse_mode="HTML"
        )
        return

    if not re.fullmatch(
        r"https?://t\.me/(?:\+)?[A-Za-z0-9_+\-/]{3,120}",
        channel_link
    ):
        await message.answer(
            "❌ Invalid CHANNEL_LINK.",
            parse_mode="HTML"
        )
        return

    try:
        chat = await bot.get_chat(lookup)
        me = await bot.get_me()
        member = await bot.get_chat_member(
            chat_id=chat.id,
            user_id=me.id
        )
        status = str(getattr(member, "status", "")).lower()

        if status not in {"administrator", "creator"}:
            await finish_admin_input(
                state,
                "❌ <b>Bot access is not ready.</b>\n\n"
                f"Destination: <b>{html.escape(str(chat.title or lookup))}</b>\n"
                "Make the bot an administrator in that channel/group, "
                "then configure it again.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="Payment Channel",
                        callback_data="admin_payment_channel",
                        style="primary"
                    )
                ]])
            )
            return

        resolved_id = str(chat.id)
        title = str(chat.title or getattr(chat, "username", None) or resolved_id)

        set_payment_setting("review_group_chat_id", resolved_id)
        set_payment_setting("review_group_link", channel_link)

        await finish_admin_input(
            state,
            "✅ <b>Payment Review Channel Saved</b>\n\n"
            f"Destination: <b>{html.escape(title)}</b>\n"
            f"Chat ID: <code>{html.escape(resolved_id)}</code>\n"
            f"Link: <b>{html.escape(channel_link)}</b>\n\n"
            "<i>New payment review requests will be sent there.</i>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Payment Channel",
                    callback_data="admin_payment_channel",
                    style="primary"
                )
            ]])
        )

    except TelegramBadRequest as exc:
        await finish_admin_input(
            state,
            "❌ <b>Telegram rejected this destination.</b>\n\n"
            f"<code>{html.escape(str(exc))}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Try Again",
                    callback_data="admin_payment_channel_edit",
                    style="primary"
                )
            ]])
        )
    except Exception as exc:
        logging.exception("Payment review channel configuration failed")
        await finish_admin_input(
            state,
            "❌ <b>Could not configure the payment channel.</b>\n\n"
            f"<code>{html.escape(str(exc))}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Try Again",
                    callback_data="admin_payment_channel_edit",
                    style="primary"
                )
            ]])
        )


@dp.callback_query(F.data == "admin_payment_channel_clear")
async def cb_admin_payment_channel_clear(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    set_payment_setting("review_group_chat_id", "")
    set_payment_setting("review_group_link", "")

    await callback.answer("Payment review channel cleared.")
    await cb_admin_payment_channel(callback)


# --- PURCHASE ANNOUNCEMENT CHANNEL ---
@dp.callback_query(F.data == "admin_purchase_channel")
async def cb_admin_purchase_channel(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    chat_id = get_bot_setting("purchase_channel_chat_id", "").strip()
    channel_link = get_bot_setting("purchase_channel_link", "").strip()

    await callback.answer()

    await safe_edit(
        callback,
        "<tg-emoji emoji-id='6039641775377748623'>📢</tg-emoji> "
        "<b>Purchase Announcement Channel</b>\n\n"
        f"Channel ID: <code>{html.escape(chat_id or 'Not configured')}</code>\n"
        f"Channel Link: <b>{html.escape(channel_link or 'Not configured')}</b>\n\n"
        "<i>After every successful order, the bot can publish a "
        "privacy-safe purchase announcement here.</i>\n\n"
        "<b>Published fields:</b> category, account group, price, order ID.\n"
        "<b>Never published:</b> OTP, password, username, user ID or private credentials."
        ,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Set / Edit Channel",
                    callback_data="admin_purchase_channel_edit",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Test Announcement",
                    callback_data="admin_purchase_channel_test",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Back to Admin Panel",
                    callback_data="admin_panel",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data == "admin_purchase_channel_edit")
async def cb_admin_purchase_channel_edit(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_purchase_channel,
        "<tg-emoji emoji-id='6039641775377748623'>📢</tg-emoji> "
        "<b>Configure Purchase Channel</b>\n\n"
        "Send:\n"
        "<code>CHAT_ID | CHANNEL_LINK</code>\n\n"
        "Example:\n"
        "<code>-1001234567890 | https://t.me/yourchannel</code>\n\n"
        "The bot must be an administrator of the channel with permission to post.\n"
        "Use <code>-</code> as the link only when the channel has no public link."
    )


@dp.message(AdminState.waiting_for_purchase_channel, F.text)
async def admin_purchase_channel_input(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message, 30)
    parts = [p.strip() for p in (message.text or "").split("|", 1)]

    if len(parts) != 2:
        await message.answer(
            "❌ Use exactly:\n"
            "<code>CHANNEL | CHANNEL_LINK</code>\n\n"
            "Examples:\n"
            "<code>-1001234567890 | https://t.me/mychannel</code>\n"
            "or\n"
            "<code>@mychannel | https://t.me/mychannel</code>",
            parse_mode="HTML"
        )
        return

    channel_ref, channel_link = parts

    # Accept numeric Telegram channel IDs, @usernames, or t.me links.
    if channel_ref == "-":
        await message.answer(
            "❌ Enter the channel ID or @username.",
            parse_mode="HTML"
        )
        return

    if re.fullmatch(r"-?\d{5,20}", channel_ref):
        lookup = channel_ref
    elif re.fullmatch(r"@[A-Za-z0-9_]{5,32}", channel_ref):
        lookup = channel_ref
    elif re.fullmatch(r"https?://t\.me/[A-Za-z0-9_]{5,32}", channel_ref):
        lookup = "@" + channel_ref.rstrip("/").split("/")[-1]
    else:
        await message.answer(
            "❌ <b>Invalid channel reference.</b>\n\n"
            "Use a numeric channel ID such as "
            "<code>-1001234567890</code> or a public "
            "<code>@channelusername</code>.",
            parse_mode="HTML"
        )
        return

    if channel_link == "-":
        channel_link = ""
    elif not re.fullmatch(r"https?://t\.me/[A-Za-z0-9_]{5,32}", channel_link):
        await message.answer(
            "❌ Invalid channel link.\n\n"
            "Use <code>https://t.me/yourchannel</code> or <code>-</code>.",
            parse_mode="HTML"
        )
        return

    try:
        # Resolve the reference through Bot API before saving it.
        chat = await bot.get_chat(lookup)
        resolved_id = str(chat.id)

        # Make sure this bot can actually post to the target channel.
        me = await bot.get_me()
        member = await bot.get_chat_member(chat_id=chat.id, user_id=me.id)
        status = str(getattr(member, "status", "")).lower()

        if status not in {"administrator", "creator"}:
            await finish_admin_input(
                state,
                "❌ <b>Channel Access Not Ready</b>\n\n"
                f"Resolved channel: <b>{html.escape(str(chat.title or 'Untitled'))}</b>\n"
                f"Chat ID: <code>{resolved_id}</code>\n"
                f"Bot status: <b>{html.escape(status or 'unknown')}</b>\n\n"
                "Add the bot to the channel as an administrator with "
                "<b>Post Messages</b> permission, then configure it again.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="Purchase Channel",
                        callback_data="admin_purchase_channel",
                        style="primary"
                    )
                ]])
            )
            return

        public_username = getattr(chat, "username", None)
        if not channel_link and public_username:
            channel_link = f"https://t.me/{public_username}"

        set_bot_setting("purchase_channel_chat_id", resolved_id)
        set_bot_setting("purchase_channel_link", channel_link)

        await finish_admin_input(
            state,
            "✅ <b>Purchase Channel Verified & Saved</b>\n\n"
            f"Channel: <b>{html.escape(str(chat.title or 'Untitled'))}</b>\n"
            f"Chat ID: <code>{html.escape(resolved_id)}</code>\n"
            f"Link: <b>{html.escape(channel_link or 'Private channel')}</b>\n"
            f"Bot access: <b>{html.escape(status)}</b>\n\n"
            "<i>The bot can now publish purchase announcements.</i>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="Test Announcement",
                        callback_data="admin_purchase_channel_test",
                        style="primary"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="Purchase Channel",
                        callback_data="admin_purchase_channel",
                        style="primary"
                    )
                ]
            ])
        )

    except TelegramBadRequest as exc:
        err = str(exc)
        lower = err.lower()

        if "chat not found" in lower:
            detail = (
                "Telegram cannot find that channel. "
                "For a private channel, use its numeric ID beginning with "
                "<code>-100</code>. For a public channel, use its "
                "<code>@username</code>."
            )
        elif "not enough rights" in lower or "administrator" in lower:
            detail = (
                "The bot is not allowed to post there. Add it as a channel "
                "administrator and enable <b>Post Messages</b>."
            )
        else:
            detail = f"<code>{html.escape(err)}</code>"

        await finish_admin_input(
            state,
            "❌ <b>Channel Verification Failed</b>\n\n" + detail,
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Try Again",
                    callback_data="admin_purchase_channel_edit",
                    style="primary"
                )
            ]])
        )

    except Exception as exc:
        logging.exception("Purchase channel verification failed")
        await finish_admin_input(
            state,
            "❌ <b>Could not verify the purchase channel.</b>\n\n"
            f"<code>{html.escape(str(exc))}</code>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Try Again",
                    callback_data="admin_purchase_channel_edit",
                    style="primary"
                )
            ]])
        )


async def publish_purchase_announcement(
    category: str,
    subcategory: str,
    price: float,
    order_id: str,
) -> bool:
    """Publish a privacy-safe completed-purchase announcement."""
    chat_ref = get_bot_setting("purchase_channel_chat_id", "").strip()
    if not chat_ref:
        return False

    channel_link = get_bot_setting("purchase_channel_link", "").strip()

    try:
        # Validate the stored destination before posting. This turns a vague
        # Telegram "chat not found" into a recoverable configuration error.
        chat = await bot.get_chat(chat_ref)
        me = await bot.get_me()
        member = await bot.get_chat_member(chat_id=chat.id, user_id=me.id)
        status = str(getattr(member, "status", "")).lower()

        if status not in {"administrator", "creator"}:
            logging.error(
                "Purchase channel bot lacks admin rights: chat=%s status=%s",
                chat.id, status
            )
            return False

        me_username = getattr(me, "username", None)
        buy_url = f"https://t.me/{me_username}" if me_username else "https://t.me/"

        text = (
            "✅ <b>New Account Purchase</b>\n\n"
            "━ Category: "
            f"<b>{html.escape(str(category or 'Account'))}</b>\n"
            "━ Account Group: "
            f"<b>{html.escape(str(subcategory or 'Account'))}</b>\n"
            "━ Price: "
            f"<b>${float(price):.2f}</b>\n"
            "━ Order: "
            f"<code>{html.escape(str(order_id))}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🔐 <i>Account credentials were delivered privately to the buyer.</i>"
        )

        keyboard = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Buy Now",
                url=buy_url,
                style="primary"
            )
        ]])

        await bot.send_message(
            chat_id=chat.id,
            text=text,
            parse_mode="HTML",
            reply_markup=keyboard
        )
        return True

    except TelegramBadRequest as exc:
        logging.error(
            "Purchase announcement Telegram error for %s: %s",
            order_id, exc
        )
        return False
    except Exception:
        logging.exception(
            "Purchase announcement failed for order %s",
            order_id
        )
        return False



@dp.callback_query(F.data == "admin_purchase_channel_test")
async def cb_admin_purchase_channel_test(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    chat_id = get_bot_setting("purchase_channel_chat_id", "").strip()
    if not chat_id:
        await callback.answer(
            "Configure a purchase channel first.",
            show_alert=True
        )
        return

    ok = await publish_purchase_announcement(
        category="Instagram",
        subcategory="2012",
        price=6.00,
        order_id="TEST-ANNOUNCEMENT"
    )

    await callback.answer(
        "Test announcement sent." if ok else "Test announcement failed.",
        show_alert=True
    )

@dp.callback_query(F.data == "admin_users")
async def cb_admin_users(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT telegram_id, username, balance FROM users ORDER BY joined_at DESC LIMIT 30")
    users = cursor.fetchall()
    conn.close()

    rows = [
        [InlineKeyboardButton(
            text=f"@{username or 'user'} • ${balance:.2f}"[:60],
            callback_data=f"adm_user_{uid}", style="primary"
        )]
        for uid, username, balance in users
    ]
    rows += [
        [InlineKeyboardButton(text="Find User by ID", callback_data="admin_find_user", style="primary")],
        [InlineKeyboardButton(text="Back to Admin Panel", callback_data="admin_panel", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
    ]
    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5033259521208747582'>👥</tg-emoji> <b>User Management</b>" + chr(10) + chr(10)
        + "<i>Select a user to manage.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data == "admin_find_user")
async def cb_admin_find_user(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    await state.set_state(AdminState.waiting_for_user_id)
    await callback.message.answer(
        "<b>Find User</b>" + chr(10) + chr(10) + "Send the Telegram user ID.",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Cancel", callback_data="admin_users", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    )


@dp.message(AdminState.waiting_for_user_id)
async def admin_user_id_input(message: types.Message, state: FSMContext):
    schedule_user_message_cleanup(message, 30)
    if not is_admin(message.from_user.id):
        return
    uid = (message.text or "").strip()
    if not uid.isdigit():
        await message.answer("Send a numeric Telegram user ID only.")
        return
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT telegram_id, username, balance, total_spent, joined_at FROM users WHERE telegram_id=?", (uid,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        await message.answer("User not found.")
        return
    await state.clear()
    await send_admin_user(message, user)


async def send_admin_user(msg, user):
    uid, username, balance, spent, joined = user
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS banned_users (telegram_id TEXT PRIMARY KEY, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    cursor.execute("SELECT 1 FROM banned_users WHERE telegram_id=?", (uid,))
    banned = cursor.fetchone() is not None
    conn.close()
    text = (
        "<tg-emoji emoji-id='5033259521208747582'>👤</tg-emoji> <b>User Management</b>"
        + chr(10) + chr(10)
        + f"Telegram ID: <code>{uid}</code>" + chr(10)
        + f"Username: @{username or 'user'}" + chr(10)
        + f"Wallet Balance: <b>${balance:.2f}</b>" + chr(10)
        + f"Total Spent: <b>${spent:.2f}</b>" + chr(10)
        + f"Member Since: {joined}" + chr(10)
        + f"Status: <b>{'BANNED' if banned else 'ACTIVE'}</b>"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Add Balance", callback_data=f"adm_add_{uid}", style="primary"),
            InlineKeyboardButton(text="Deduct Balance", callback_data=f"adm_deduct_{uid}", style="primary")
        ],
        [
            InlineKeyboardButton(text="View History", callback_data=f"adm_hist_{uid}", style="primary"),
            InlineKeyboardButton(text="Ban / Unban", callback_data=f"adm_ban_{uid}", style="primary")
        ],
        [InlineKeyboardButton(text="Back to Users", callback_data="admin_users", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)],
        [InlineKeyboardButton(text="Admin Panel", callback_data="admin_panel", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
    ])
    await msg.answer(text, parse_mode="HTML", reply_markup=kb)


@dp.callback_query(F.data.startswith("adm_user_"))
async def cb_admin_user(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    uid=callback.data.replace("adm_user_","",1)
    await callback.answer()
    await render_admin_user_callback(callback,uid)


@dp.message(AdminState.waiting_for_history_user_id)
async def admin_history_user_id_input(message: types.Message, state: FSMContext):
    schedule_user_message_cleanup(message, 30)
    if not is_admin(message.from_user.id):
        return

    uid = (message.text or "").strip()
    if not uid.isdigit():
        await message.answer("Send a numeric Telegram user ID only.")
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT type, title, amount, balance_before, balance_after, created_at, reference_id
        FROM wallet_transactions
        WHERE telegram_id=?
        ORDER BY created_at DESC LIMIT 50
    """, (uid,))
    txns = cursor.fetchall()
    conn.close()

    await state.clear()

    if not txns:
        body = "<i>No transactions recorded for this user.</i>"
    else:
        body = (chr(10) + chr(10)).join(
            f"<b>{title}</b> <code>{'+' if amount > 0 else ''}${amount:.2f}</code>"
            + chr(10)
            + f"<i>{created_at} • Before ${before:.2f} • After ${after:.2f} • Ref {ref}</i>"
            for typ, title, amount, before, after, created_at, ref in txns
        )

    result_text = (
        "<tg-emoji emoji-id='5895444149699612825'>📊</tg-emoji> "
        "<b>User Transaction History</b>" + chr(10) + chr(10)
        + f"User: <code>{uid}</code>" + chr(10) + chr(10) + body
    )
    if await finish_admin_input(
        state,
        result_text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Back to Admin Panel", callback_data="admin_panel",
                                  style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    ):
        return
    await message.answer(result_text, parse_mode="HTML")


@dp.callback_query(F.data.startswith("adm_add_"))
async def cb_admin_add(callback: types.CallbackQuery, state: FSMContext):
    await admin_balance_prompt(callback, state, "add")


@dp.callback_query(F.data.startswith("adm_deduct_"))
async def cb_admin_deduct(callback: types.CallbackQuery, state: FSMContext):
    await admin_balance_prompt(callback, state, "deduct")


async def admin_balance_prompt(callback, state, action):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    uid = callback.data.split("_", 2)[2]
    await state.update_data(admin_user_id=uid, balance_action=action)
    await state.set_state(AdminState.waiting_for_balance_change)
    await callback.message.answer(
        f"<b>{'Add' if action == 'add' else 'Deduct'} Balance</b>" + chr(10) + chr(10)
        + "Send the USD amount as a number only." + chr(10)
        + "Example: <code>25</code>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Cancel", callback_data=f"adm_user_{uid}", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    )


@dp.message(AdminState.waiting_for_balance_change)
async def admin_balance_change_input(message: types.Message, state: FSMContext):
    schedule_user_message_cleanup(message, 30)
    if not is_admin(message.from_user.id):
        return
    try:
        amount = float((message.text or "").strip())
        if amount <= 0:
            raise ValueError
    except ValueError:
        await message.answer("Send a valid positive number only.")
        return
    data = await state.get_data()
    uid = data["admin_user_id"]
    action = data["balance_action"]

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE telegram_id=?", (uid,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        await state.clear()
        await message.answer("User not found.")
        return
    before = float(row[0] or 0)
    after = before + amount if action == "add" else before - amount
    if after < 0:
        conn.close()
        await message.answer("Cannot deduct more than the user's balance.")
        return
    cursor.execute("UPDATE users SET balance=? WHERE telegram_id=?", (after, uid))
    conn.commit()
    conn.close()

    signed = amount if action == "add" else -amount
    log_transaction(uid, "admin_adjustment", "Admin Balance Adjustment", signed, before, after, f"ADMIN-{message.from_user.id}")
    await state.clear()
    await message.answer(
        "<b>Balance Updated</b>" + chr(10) + chr(10)
        + f"User: <code>{uid}</code>" + chr(10)
        + f"Change: <b>{'+' if signed > 0 else ''}${signed:.2f}</b>" + chr(10)
        + f"New Balance: <b>${after:.2f}</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Back to User", callback_data=f"adm_user_{uid}", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)],
            [InlineKeyboardButton(text="Admin Panel", callback_data="admin_panel", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
        ])
    )


@dp.callback_query(F.data.startswith("adm_ban_"))
async def cb_admin_ban(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    uid=callback.data.replace("adm_ban_","",1)

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        user=conn.execute(
            "SELECT telegram_id FROM users WHERE telegram_id=?",
            (uid,)
        ).fetchone()
        if not user:
            await callback.answer("User not found.",show_alert=True)
            return

        conn.execute(
            "CREATE TABLE IF NOT EXISTS banned_users "
            "(telegram_id TEXT PRIMARY KEY, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        exists=conn.execute(
            "SELECT 1 FROM banned_users WHERE telegram_id=?",(uid,)
        ).fetchone()

        if exists:
            conn.execute("DELETE FROM banned_users WHERE telegram_id=?",(uid,))
            action="unbanned"
        else:
            conn.execute("INSERT OR IGNORE INTO banned_users(telegram_id) VALUES(?)",(uid,))
            action="banned"

        conn.commit()
    finally:
        conn.close()

    await callback.answer(f"User {action}.",show_alert=True)
    await render_admin_user_callback(callback,uid)


async def render_admin_user_callback(callback:types.CallbackQuery, uid:str):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        user=conn.execute(
            "SELECT telegram_id, username, balance, total_spent, joined_at "
            "FROM users WHERE telegram_id=?",(uid,)
        ).fetchone()
        if not user:
            await callback.answer("User not found.",show_alert=True)
            return
        conn.execute(
            "CREATE TABLE IF NOT EXISTS banned_users "
            "(telegram_id TEXT PRIMARY KEY, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        banned=bool(conn.execute(
            "SELECT 1 FROM banned_users WHERE telegram_id=?",(uid,)
        ).fetchone())
    finally:
        conn.close()

    _,username,balance,spent,joined=user
    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5033259521208747582'>👤</tg-emoji> "
        "<b>User Management</b>\\n\\n"
        f"Telegram ID: <code>{uid}</code>\\n"
        f"Username: @{html.escape(username or 'user')}\\n"
        f"Wallet Balance: <b>${float(balance or 0):.2f}</b>\\n"
        f"Total Spent: <b>${float(spent or 0):.2f}</b>\\n"
        f"Member Since: {html.escape(str(joined))}\\n"
        f"Status: <b>{'BANNED' if banned else 'ACTIVE'}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="Add Balance",callback_data=f"adm_add_{uid}",style="primary"),
                InlineKeyboardButton(text="Deduct Balance",callback_data=f"adm_deduct_{uid}",style="primary")
            ],
            [
                InlineKeyboardButton(text="View History",callback_data=f"adm_hist_{uid}",style="primary"),
                InlineKeyboardButton(text=("Unban User" if banned else "Ban User"),callback_data=f"adm_ban_{uid}",style="danger" if not banned else "success")
            ],
            [
                InlineKeyboardButton(text="Back to Users",callback_data="admin_users",style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)
            ]
        ])
    )


@dp.callback_query(F.data.startswith("adm_hist_"))
async def cb_admin_user_history(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return

    uid=callback.data.replace("adm_hist_","",1)
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        exists=conn.execute("SELECT 1 FROM users WHERE telegram_id=?",(uid,)).fetchone()
        if not exists:
            await callback.answer("User not found.",show_alert=True)
            return
        txns=conn.execute(
            "SELECT type,title,amount,balance_before,balance_after,created_at,reference_id "
            "FROM wallet_transactions WHERE telegram_id=? ORDER BY created_at DESC LIMIT 50",
            (uid,)
        ).fetchall()
    finally:
        conn.close()

    await callback.answer()
    if not txns:
        body="<i>No transactions recorded for this user.</i>"
    else:
        body="\n\n".join(
            f"<b>{html.escape(str(title))}</b> "
            f"<code>{'+' if float(amount)>0 else ''}${float(amount):.2f}</code>\n"
            f"<i>{html.escape(str(created_at))} • Before ${float(before):.2f} • "
            f"After ${float(after):.2f} • Ref {html.escape(str(ref or '—'))}</i>"
            for typ,title,amount,before,after,created_at,ref in txns
        )

    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5895444149699612825'>📊</tg-emoji> "
        "<b>User Transaction History</b>\n\n"
        f"User: <code>{uid}</code>\n\n{body}",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Back to User",
                callback_data=f"adm_user_{uid}",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )


@dp.callback_query(F.data == "admin_user_history")
async def cb_admin_user_history_lookup(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    await begin_admin_input(
        callback,state,AdminState.waiting_for_history_user_id,
        "<tg-emoji emoji-id='5895444149699612825'>📊</tg-emoji> "
        "<b>User History</b>"+chr(10)+chr(10)
        +"<i>Send the user's Telegram ID.</i>"
    )

@dp.callback_query(F.data == "admin_deposits")
async def cb_admin_deposits(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, telegram_id, username, amount, txn_id, screenshot_url, status, created_at
        FROM deposits ORDER BY created_at DESC LIMIT 30
    """)
    deposits = cursor.fetchall()
    conn.close()

    chunks, buttons = [], []

    for dep_id, uid, username, amount, txn_id, screenshot, status, created in deposits:
        chunks.append(
            f"<b>{dep_id}</b> • <b>{status.upper()}</b>" + chr(10)
            + f"User: @{username or 'user'} (<code>{uid}</code>)" + chr(10)
            + f"Amount: <b>${amount:.2f}</b>" + chr(10)
            + f"TXN ID: <code>{txn_id}</code>" + chr(10)
            + f"Payment SS: <b>{'Attached' if screenshot else 'Not attached'}</b>" + chr(10)
            + f"<i>{created}</i>"
        )

        action_row = []
        if screenshot:
            action_row.append(
                InlineKeyboardButton(
                    text=f"View SS {dep_id}",
                    callback_data=f"adm_ss_{dep_id}",
                    style="primary",
                    icon_custom_emoji_id="5224257782013769471"
                )
            )
        action_row.append(
            InlineKeyboardButton(
                text=f"User {uid}",
                callback_data=f"adm_user_{uid}",
                style="primary",
                icon_custom_emoji_id=PROFILE_EMOJI_ID
            )
        )
        buttons.append(action_row)

        if status == "pending":
            buttons.append([
                InlineKeyboardButton(
                    text=f"Approve {dep_id}",
                    callback_data=f"adm_appr_{dep_id}",
                    style="primary",
                    icon_custom_emoji_id="6039641775377748623"
                ),
                InlineKeyboardButton(
                    text=f"Reject {dep_id}",
                    callback_data=f"adm_rej_{dep_id}",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ])

    body = (chr(10) + chr(10)).join(chunks) if chunks else "<i>No payment history found.</i>"
    buttons.append([
        InlineKeyboardButton(
            text="Back to Admin Panel",
            callback_data="admin_panel",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        "<tg-emoji emoji-id='5224257782013769471'>💳</tg-emoji> "
        "<b>Payment History</b>" + chr(10) + chr(10) + body,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons)
    )


@dp.callback_query(F.data.startswith("adm_ss_"))
async def cb_admin_payment_proof(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    dep_id = callback.data.replace("adm_ss_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT telegram_id, username, amount, txn_id, screenshot_url, status, created_at
        FROM deposits WHERE id=?
    """, (dep_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        await callback.answer("Payment not found.", show_alert=True)
        return

    uid, username, amount, txn_id, proof, status, created = row
    if not proof:
        await callback.answer("No payment proof attached.", show_alert=True)
        return

    await callback.answer()
    caption = (
        f"<b>Payment Proof</b>" + chr(10) + chr(10)
        + f"Request: <code>{dep_id}</code>" + chr(10)
        + f"User: @{username or 'user'} (<code>{uid}</code>)" + chr(10)
        + f"Amount: <b>${amount:.2f}</b>" + chr(10)
        + f"TXN ID: <code>{txn_id}</code>" + chr(10)
        + f"Status: <b>{status.upper()}</b>" + chr(10)
        + f"Submitted: {created}"
    )

    try:
        await bot.send_photo(
            chat_id=callback.from_user.id,
            photo=proof,
            caption=caption,
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="Back to Payments", callback_data="admin_deposits", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
            ])
        )
    except Exception:
        # Documents may be stored in screenshot_url as a document file_id.
        try:
            await bot.send_document(
                chat_id=callback.from_user.id,
                document=proof,
                caption=caption,
                parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="Back to Payments", callback_data="admin_deposits", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
                ])
            )
        except Exception as exc:
            logging.exception("Could not send payment proof: %s", exc)
            await callback.answer("Could not open payment proof.", show_alert=True)




@dp.callback_query(F.data == "admin_stats")
async def cb_admin_stats(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        users=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] or 0
        banned=conn.execute(
            "SELECT COUNT(*) FROM banned_users"
        ).fetchone()[0] if conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='banned_users'"
        ).fetchone() else 0
        orders=conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0] or 0
        completed_orders=conn.execute(
            "SELECT COUNT(*) FROM orders WHERE status='completed'"
        ).fetchone()[0] or 0
        revenue=conn.execute(
            "SELECT COALESCE(SUM(price),0) FROM orders WHERE status='completed'"
        ).fetchone()[0] or 0
        payments=conn.execute("SELECT COUNT(*) FROM deposits").fetchone()[0] or 0
        pending_payments=conn.execute(
            "SELECT COUNT(*) FROM deposits WHERE status='pending'"
        ).fetchone()[0] or 0
        approved_payments=conn.execute(
            "SELECT COUNT(*) FROM deposits WHERE status='approved'"
        ).fetchone()[0] or 0
        stock=conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE stock_count>0"
        ).fetchone()[0] or 0
        categories=conn.execute(
            "SELECT COUNT(*) FROM store_categories"
        ).fetchone()[0] or 0
        enabled_categories=conn.execute(
            "SELECT COUNT(*) FROM store_categories WHERE enabled=1"
        ).fetchone()[0] or 0
        promo_codes=conn.execute(
            "SELECT COUNT(*) FROM promo_codes"
        ).fetchone()[0] or 0
        active_promos=conn.execute(
            "SELECT COUNT(*) FROM promo_codes WHERE is_active=1"
        ).fetchone()[0] or 0
    finally:
        conn.close()

    await safe_edit(
        callback,
        "📊 <b>Bot Statistics</b>\n\n"
        f"Users: <b>{users}</b>\n"
        f"Banned Users: <b>{banned}</b>\n\n"
        f"Orders: <b>{orders}</b>\n"
        f"Completed Orders: <b>{completed_orders}</b>\n"
        f"Sales Volume: <b>${float(revenue):.2f}</b>\n\n"
        f"Payments: <b>{payments}</b>\n"
        f"Pending Payments: <b>{pending_payments}</b>\n"
        f"Approved Payments: <b>{approved_payments}</b>\n\n"
        f"Available Accounts: <b>{stock}</b>\n"
        f"Categories: <b>{categories}</b> "
        f"(<b>{enabled_categories}</b> enabled)\n"
        f"Promo Codes: <b>{promo_codes}</b> "
        f"(<b>{active_promos}</b> active)",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Refresh",
                    callback_data="admin_stats",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Back to Admin Panel",
                    callback_data="admin_panel",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )

@dp.callback_query(F.data == "admin_broadcast")
async def cb_admin_broadcast(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    await begin_admin_input(
        callback,state,AdminState.waiting_for_broadcast,
        "<tg-emoji emoji-id='6039641775377748623'>📢</tg-emoji> "
        "<b>Broadcast Center</b>"+chr(10)+chr(10)
        +"<i>Forward or send the message you want to broadcast.</i>"
    )

@dp.message(AdminState.waiting_for_broadcast)
async def admin_broadcast_input(message: types.Message, state: FSMContext):
    schedule_user_message_cleanup(message, 30)
    if not is_admin(message.from_user.id):
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT telegram_id FROM users")
    ids = [r[0] for r in cursor.fetchall()]
    conn.close()

    sent = failed = 0

    # copy_message preserves the original Telegram message payload instead of
    # rebuilding it as plain text. This is essential for premium stickers and
    # custom emoji entities.
    for uid in ids:
        try:
            await bot.copy_message(
                chat_id=int(uid),
                from_chat_id=message.chat.id,
                message_id=message.message_id
            )
            sent += 1
        except Exception as exc:
            failed += 1
            logging.warning("Broadcast failed for %s: %s", uid, exc)

    await state.clear()
    result_text = (
        "<tg-emoji emoji-id='6039641775377748623'>📢</tg-emoji> "
        "<b>Broadcast Complete</b>" + chr(10) + chr(10)
        + f"Delivered: <b>{sent}</b>" + chr(10)
        + f"Failed: <b>{failed}</b>"
    )
    if await finish_admin_input(state,result_text,reply_markup=get_admin_menu()):
        return
    await message.answer(result_text,parse_mode="HTML")



# --- STORE & STOCK MANAGER ---
STORE_STYLES={"primary","success","danger"}


def store_categories(enabled_only=False):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        q="SELECT key,name,button_style,sticker_id,sort_order,enabled FROM store_categories"
        if enabled_only:q+=" WHERE enabled=1"
        q+=" ORDER BY sort_order,key"
        return conn.execute(q).fetchall()
    finally: conn.close()

def store_category(key):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:return conn.execute("SELECT key,name,button_style,sticker_id,sort_order,enabled FROM store_categories WHERE key=?",(key,)).fetchone()
    finally:conn.close()

def store_subs(key,enabled_only=False):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        q="SELECT id,name,button_style,sticker_id,sort_order,enabled FROM store_subcategories WHERE category_key=?"
        if enabled_only:q+=" AND enabled=1"
        q+=" ORDER BY sort_order,name"
        return conn.execute(q,(key,)).fetchall()
    finally:conn.close()

def store_sub(sid):
    conn=sqlite3.connect("bot.db", timeout=30)
    try:return conn.execute("SELECT id,category_key,name,button_style,sticker_id,sort_order,enabled FROM store_subcategories WHERE id=?",(sid,)).fetchone()
    finally:conn.close()

def safe_style(v): return v if v in {"primary","success","danger"} else "primary"

def category_key_by_name(name: str):
    for key, cat_name, *_ in store_categories():
        if cat_name == name:
            return key
    return None


def rich_emoji(emoji_id: str, fallback: str = "•") -> str:
    return f"<tg-emoji emoji-id='{emoji_id}'>{fallback}</tg-emoji>"




# --- ADMIN PROMO CODES ---
@dp.callback_query(F.data == "admin_promos")
async def cb_admin_promos(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        rows_data=conn.execute(
            "SELECT id,code,reward_type,reward_value,max_uses,used_count,"
            "per_user_limit,expires_at,is_active "
            "FROM promo_codes ORDER BY rowid DESC LIMIT 40"
        ).fetchall()
    finally:
        conn.close()

    buttons=[]
    body=[]
    for pid,code,rtype,rval,max_uses,used_count,per_user,expires,active in rows_data:
        status="ON" if active else "OFF"
        reward=(f"{float(rval):.2f}%" if rtype=="percent" else f"${float(rval):.2f}")
        body.append(
            f"<b>{html.escape(code)}</b> • <b>{status}</b>\n"
            f"Reward: <b>{reward}</b> • Uses: <b>{used_count}/{max_uses}</b>\n"
            f"Per user: <b>{per_user}</b> • Expiry: <b>{html.escape(str(expires or 'None'))}</b>"
        )
        buttons.append([
            InlineKeyboardButton(
                text=("Disable " if active else "Enable ")+code,
                callback_data=f"adm_promo_toggle_{pid}",
                style="danger" if active else "success"
            )
        ])

    rows=[
        [
            InlineKeyboardButton(
                text="Create Promo Code",
                callback_data="admin_promo_create",
                style="success",
                icon_custom_emoji_id=PROMO_CODES_EMOJI_ID
            )
        ]
    ]
    rows.extend(buttons)
    rows.append([
        InlineKeyboardButton(
            text="Back to Admin Panel",
            callback_data="admin_panel",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    body_text="\n\n".join(body) if body else "<i>No promo codes created yet.</i>"
    await safe_edit(
        callback,
        "🎟️ <b>Promo Codes</b>\n\n"
        "<i>Create and manage user bonus codes.</i>\n\n"
        + body_text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data == "admin_promo_create")
async def cb_admin_promo_create(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return
    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_promo_create,
        "🎟️ <b>Create Promo Code</b>\n\n"
        "Send one line in this format:\n"
        "<code>CODE | REWARD | MAX_USES | PER_USER | MIN_BALANCE | EXPIRY</code>\n\n"
        "Examples:\n"
        "<code>WELCOME100 | 100 | 50 | 1 | 0 | 2026-12-31</code>\n"
        "<code>VIP10 | 10% | 100 | 1 | 0 | -</code>\n\n"
        "<i>Use - for no expiry.</i>"
    )


@dp.message(AdminState.waiting_for_promo_create,F.text)
async def admin_promo_create_input(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message,30)
    parts=[p.strip() for p in (message.text or "").split("|")]
    if len(parts)!=6:
        await message.answer(
            "❌ <b>Invalid format.</b>\n\n"
            "Use:\n<code>CODE | REWARD | MAX_USES | PER_USER | MIN_BALANCE | EXPIRY</code>",
            parse_mode="HTML"
        )
        return

    code,reward_s,max_s,per_user_s,min_bal_s,expiry=parts
    code=code.upper()
    if not re.fullmatch(r"[A-Z0-9_-]{3,32}",code):
        await message.answer(
            "❌ Code must be 3–32 characters using A-Z, 0-9, _ or -.",
            parse_mode="HTML"
        )
        return

    try:
        if reward_s.endswith("%"):
            reward_type="percent"
            reward_value=float(reward_s[:-1])
            if reward_value<=0 or reward_value>100:
                raise ValueError
        else:
            reward_type="fixed"
            reward_value=float(reward_s)
            if reward_value<=0:
                raise ValueError
        max_uses=int(max_s)
        per_user=int(per_user_s)
        min_bal=float(min_bal_s)
        if max_uses<=0 or per_user<=0 or min_bal<0:
            raise ValueError
    except ValueError:
        await message.answer(
            "❌ <b>Invalid reward or limit.</b>\n\n"
            "Check reward, MAX_USES, PER_USER and MIN_BALANCE.",
            parse_mode="HTML"
        )
        return

    if expiry=="-":
        expiry_db=None
    else:
        try:
            datetime.strptime(expiry,"%Y-%m-%d")
            expiry_db=expiry
        except ValueError:
            await message.answer(
                "❌ Expiry must be <code>YYYY-MM-DD</code> or <code>-</code>.",
                parse_mode="HTML"
            )
            return

    promo_id=f"PROMO-{int(datetime.now().timestamp()*1000)}"
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        if conn.execute(
            "SELECT 1 FROM promo_codes WHERE UPPER(code)=?",
            (code,)
        ).fetchone():
            await message.answer(
                f"❌ Promo code <code>{html.escape(code)}</code> already exists.",
                parse_mode="HTML"
            )
            return
        conn.execute(
            "INSERT INTO promo_codes "
            "(id,code,reward_type,reward_value,max_uses,used_count,"
            "per_user_limit,min_wallet_req,expires_at,is_active) "
            "VALUES(?,?,?,?,?,?,?,?,?,1)",
            (
                promo_id,code,reward_type,reward_value,max_uses,0,
                per_user,min_bal,expiry_db
            )
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logging.exception("Admin promo creation failed")
        await message.answer(
            "❌ <b>Promo creation failed.</b>\n\nDatabase error.",
            parse_mode="HTML"
        )
        return
    finally:
        conn.close()

    await finish_admin_input(
        state,
        "✅ <b>Promo Code Created</b>\n\n"
        f"Code: <code>{html.escape(code)}</code>\n"
        f"Reward: <b>{html.escape(reward_s)}</b>\n"
        f"Max Uses: <b>{max_uses}</b>\n"
        f"Per User: <b>{per_user}</b>\n"
        f"Min Balance: <b>${min_bal:.2f}</b>\n"
        f"Expiry: <b>{html.escape(str(expiry_db or 'None'))}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Back to Promo Codes",
                    callback_data="admin_promos",
                    style="primary"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Admin Panel",
                    callback_data="admin_panel",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("adm_promo_toggle_"))
async def cb_admin_promo_toggle(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    pid=callback.data.replace("adm_promo_toggle_","",1)
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        row=conn.execute("SELECT is_active,code FROM promo_codes WHERE id=?",(pid,)).fetchone()
        if not row:
            await callback.answer("Promo code not found.",show_alert=True)
            return
        new_active=0 if row[0] else 1
        conn.execute("UPDATE promo_codes SET is_active=? WHERE id=?",(new_active,pid))
        conn.commit()
        code=row[1]
    finally:
        conn.close()

    await callback.answer(f"{code} {'enabled' if new_active else 'disabled'}.")
    await cb_admin_promos(callback)


@dp.callback_query(F.data == "admin_store")
async def cb_admin_store(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    cats = store_categories()
    category_buttons = []

    for key, name, style, sticker, order, enabled in cats:
        conn = sqlite3.connect("bot.db", timeout=30)
        try:
            stock = conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE category=? AND stock_count>0",
                (name,)
            ).fetchone()[0] or 0
        finally:
            conn.close()

        label = f"{name}  •  {stock}"
        if not enabled:
            label = f"{name}  •  OFF"

        category_buttons.append(
            InlineKeyboardButton(
                text=label,
                callback_data=f"adm_cat_{key}",
                style=safe_style(style),
                icon_custom_emoji_id=(sticker or DEFAULT_CATEGORY_STICKERS.get(key) or None)
            )
        )

    rows = [category_buttons[i:i+2] for i in range(0, len(category_buttons), 2)]
    rows += [
        [
            InlineKeyboardButton(
                text="Add Category",
                callback_data="adm_cat_add",
                style="success"
            ),
            InlineKeyboardButton(
                text="Add Account",
                callback_data="adm_stock_add",
                style="primary"
            )
        ],
        [
            InlineKeyboardButton(
                text="Back to Admin",
                callback_data="admin_panel",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]
    ]

    await safe_edit(
        callback,
        rich_emoji("5042302287087666158", "📦") + " <b>Store & Stock</b>\n\n"
        "<i>Select a category to manage it.</i>\n"
        "<i>Number shown on a category = available accounts.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )

@dp.callback_query(F.data == "admin_stock")
async def cb_admin_stock_compat(callback: types.CallbackQuery):
    await cb_admin_store(callback)

@dp.callback_query(F.data == "adm_cat_add")
async def cb_admin_cat_add(callback: types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id): await callback.answer("Unauthorized access.",show_alert=True); return
    await callback.answer(); await state.set_state(AdminState.waiting_for_category_name)
    await safe_edit(callback,"<b>Add Category</b>\n\nSend the category name. Example: <code>Instagram</code>",reply_markup=InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="Cancel",callback_data="admin_store",style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)]]))

@dp.message(AdminState.waiting_for_category_name,F.text)
async def admin_cat_name(message:types.Message,state:FSMContext):
    if not is_admin(message.from_user.id): return
    schedule_user_message_cleanup(message,30); name=message.text.strip()
    if not 1<=len(name)<=50: await message.answer("Category name must be 1–50 characters."); return
    key=re.sub(r"[^a-z0-9]+","_",name.lower()).strip("_") or f"cat_{int(datetime.now().timestamp())}"
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        if conn.execute("SELECT 1 FROM store_categories WHERE key=? OR lower(name)=lower(?)",(key,name)).fetchone(): await message.answer("That category already exists."); return
        conn.execute("INSERT INTO store_categories(key,name,button_style,sticker_id,sort_order,enabled) VALUES(?,?,?,?,?,1)",(key,name,"primary","",999)); conn.commit()
    finally: conn.close()
    await finish_admin_input(
        state,
        f"✅ <b>Category Created</b>\n\n<b>{html.escape(name)}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Back to Store",
                callback_data="admin_store",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )

@dp.callback_query(F.data.regexp(r"^adm_cat_(?!add$|style_|toggle_|delete_).+$"))
async def cb_admin_cat(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    key=callback.data.replace("adm_cat_","",1)
    if key == "add" or key.startswith(("style_","toggle_","delete_")):
        return

    cat=store_category(key)
    if not cat:
        await callback.answer("Category not found.",show_alert=True)
        return

    await callback.answer()
    _,name,style,sticker,order,enabled=cat

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        subs=store_subs(key)
        stock=conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE category=? AND stock_count>0",
            (name,)
        ).fetchone()[0] or 0
    finally:
        conn.close()

    sub_buttons=[]
    for sid,sname,sstyle,ssticker,_,senabled in subs:
        sub_stock=0
        conn=sqlite3.connect("bot.db", timeout=30)
        try:
            sub_stock=conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE subcategory_id=? AND stock_count>0",
                (sid,)
            ).fetchone()[0] or 0
        finally:
            conn.close()
        label=f"{sname}  •  {sub_stock}"
        if not senabled:
            label=f"{sname}  •  OFF"
        sub_buttons.append(
            InlineKeyboardButton(
                text=label,
                callback_data=f"adm_sub_{sid}",
                style=safe_style(sstyle),
                icon_custom_emoji_id=(ssticker or None)
            )
        )

    rows=[
        [
            InlineKeyboardButton(
                text="Add Account",
                callback_data=f"adm_account_cat_{key}",
                style="success"
            ),
            InlineKeyboardButton(
                text="Add Subcategory",
                callback_data=f"adm_sub_add_{key}",
                style="primary"
            )
        ],
        [
            InlineKeyboardButton(
                text=("Disable Category" if enabled else "Enable Category"),
                callback_data=f"adm_cat_toggle_{key}",
                style="primary"
            ),
            InlineKeyboardButton(
                text="Edit Style",
                callback_data=f"adm_cat_style_{key}",
                style="primary"
            )
        ],
    ]

    if sub_buttons:
        rows += [sub_buttons[i:i+2] for i in range(0,len(sub_buttons),2)]
    else:
        rows.append([
            InlineKeyboardButton(
                text="No Subcategories Yet",
                callback_data=f"adm_sub_add_{key}",
                style="primary"
            )
        ])

    rows += [
        [
            InlineKeyboardButton(
                text="Delete Category",
                callback_data=f"adm_cat_delete_{key}",
                style="danger"
            )
        ],
        [
            InlineKeyboardButton(
                text="Back to Store",
                callback_data="admin_store",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]
    ]

    await safe_edit(
        callback,
        f"📁 <b>{html.escape(name)}</b>\n\n"
        f"Status: <b>{'Enabled' if enabled else 'Disabled'}</b>\n"
        f"Available accounts: <b>{stock}</b>\n"
        f"Subcategories: <b>{len(subs)}</b>\n\n"
        "<i>Select a subcategory below or add an account directly.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )

@dp.callback_query(F.data.startswith("adm_cat_style_"))
async def cb_admin_cat_style(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    key=callback.data.replace("adm_cat_style_","",1)
    if not store_category(key):
        await callback.answer("Category not found.",show_alert=True); return
    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_category_style,
        "<b>Edit Category Style</b>\n\n"
        "Send <code>COLOR STICKER_ID</code>.\n"
        "Colors: <code>primary</code> <code>success</code> <code>danger</code>.\n"
        "Use <code>-</code> for no sticker."
    )
    await state.update_data(store_category_key=key)

@dp.message(AdminState.waiting_for_category_style,F.text)
async def admin_cat_style(message:types.Message,state:FSMContext):
    if not is_admin(message.from_user.id):
        return
    schedule_user_message_cleanup(message,30)
    p=(message.text or "").strip().split(maxsplit=1)
    if len(p)!=2 or p[0] not in {"primary","success","danger"}:
        await message.answer(
            "Use: <code>primary STICKER_ID</code>\n"
            "Example: <code>success 6041705726206808304</code>\n"
            "Use <code>-</code> for no sticker.",
            parse_mode="HTML"
        )
        return
    d=await state.get_data()
    key=d.get("store_category_key")
    if not store_category(key):
        await state.clear()
        await message.answer("Category not found.",parse_mode="HTML")
        return
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute(
            "UPDATE store_categories SET button_style=?,sticker_id=? WHERE key=?",
            (p[0],"" if p[1]=="-" else p[1].strip(),key)
        )
        conn.commit()
    finally:
        conn.close()
    result=(
        "<b>Category style updated.</b>\n\n"
        f"Category: <b>{html.escape(store_category(key)[1])}</b>"
    )
    await finish_admin_input(
        state,
        result,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Back to Store",
                callback_data="admin_store",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )

@dp.callback_query(F.data.startswith("adm_cat_toggle_"))
async def cb_admin_cat_toggle(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    key=callback.data.replace("adm_cat_toggle_","",1)
    cat=store_category(key)
    if not cat:
        await callback.answer("Category not found.",show_alert=True); return
    new_enabled=0 if int(cat[5]) else 1
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute("UPDATE store_categories SET enabled=? WHERE key=?",(new_enabled,key))
        conn.commit()
    finally:
        conn.close()
    await callback.answer("Category enabled." if new_enabled else "Category disabled.")
    await cb_admin_cat(callback)


@dp.callback_query(F.data.startswith("adm_cat_delete_"))
async def cb_admin_category_delete_confirm(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    key = callback.data.replace("adm_cat_delete_", "", 1)
    cat = store_category(key)
    if not cat:
        await callback.answer("Category not found.", show_alert=True)
        return

    await callback.answer()
    name = cat[1]
    await safe_edit(
        callback,
        "⚠️ <b>Delete Category</b>\n\n"
        f"You are about to delete <b>{html.escape(name)}</b>.\n\n"
        "<b>This removes:</b>\n"
        "• The category\n"
        "• All subcategories\n"
        "• All products/accounts inside it\n"
        "• Their encrypted credential records\n\n"
        "<i>This action cannot be undone.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="YES, DELETE",
                    callback_data=f"adm_cat_delete_yes_{key}",
                    style="danger"
                ),
                InlineKeyboardButton(
                    text="Cancel",
                    callback_data=f"adm_cat_{key}",
                    style="primary",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("adm_cat_delete_yes_"))
async def cb_admin_category_delete(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    key = callback.data.replace("adm_cat_delete_yes_", "", 1)
    cat = store_category(key)
    if not cat:
        await callback.answer("Category not found.", show_alert=True)
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        account_rows = conn.execute(
            "SELECT id FROM accounts WHERE category=?",
            (cat[1],)
        ).fetchall()
        conn.execute("DELETE FROM accounts WHERE category=?", (cat[1],))
        conn.execute("DELETE FROM store_subcategories WHERE category_key=?", (key,))
        conn.execute("DELETE FROM store_categories WHERE key=?", (key,))
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logging.exception("Category deletion failed")
        await callback.answer("Could not delete category.", show_alert=True)
        return
    finally:
        conn.close()

    # Remove encrypted credentials belonging to deleted inventory.
    for (account_id,) in account_rows:
        try:
            delete_account_credentials(str(account_id))
        except Exception:
            logging.exception("Could not delete credentials for account %s", account_id)

    await callback.answer("Category deleted.")
    await cb_admin_store(callback)


@dp.callback_query(F.data.startswith("adm_sub_add_"))
async def cb_admin_sub_add(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return
    key=callback.data.replace("adm_sub_add_","",1)
    if not store_category(key):
        await callback.answer("Category not found.",show_alert=True)
        return
    await callback.answer()
    await state.set_state(AdminState.waiting_for_subcategory_name)
    await state.update_data(store_category_key=key)
    await safe_edit(
        callback,
        "📂 <b>New Subcategory</b>\n\n"
        "Send the subcategory name.\n\n"
        "Example:\n<code>2K12</code>\n<code>2K14</code>\n<code>2010</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Cancel",
                callback_data=f"adm_cat_{key}",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )


@dp.message(AdminState.waiting_for_subcategory_name,F.text)
async def admin_sub_name(message:types.Message,state:FSMContext):
    if not is_admin(message.from_user.id): return
    schedule_user_message_cleanup(message,30); d=await state.get_data(); name=message.text.strip()
    sid=f"SUB-{int(datetime.now().timestamp()*1000)}"; conn=sqlite3.connect("bot.db", timeout=30)
    try: conn.execute("INSERT INTO store_subcategories(id,category_key,name,button_style,sticker_id,sort_order,enabled) VALUES(?,?,?,?,?,?,1)",(sid,d["store_category_key"],name,"primary","",999)); conn.commit()
    except sqlite3.IntegrityError: await message.answer("That subcategory already exists."); return
    finally: conn.close()
    await finish_admin_input(
        state,
        f"✅ <b>Subcategory Created</b>\n\n<b>{html.escape(name)}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Back to Category",
                callback_data=f"adm_cat_{d['store_category_key']}",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )

@dp.callback_query(F.data.startswith("adm_sub_style_"))
async def cb_admin_sub_style(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    sid=callback.data.replace("adm_sub_style_","",1)
    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True); return
    await callback.answer()
    await begin_admin_input(
        callback,
        state,
        AdminState.waiting_for_subcategory_style,
        "<b>Edit Subcategory Style</b>\n\n"
        "Send <code>COLOR STICKER_ID</code>.\n"
        "Colors: <code>primary</code> <code>success</code> <code>danger</code>.\n"
        "Use <code>-</code> for no sticker."
    )
    await state.update_data(store_sub_id=sid)

@dp.message(AdminState.waiting_for_subcategory_style,F.text)
async def admin_sub_style(message:types.Message,state:FSMContext):
    if not is_admin(message.from_user.id): return
    schedule_user_message_cleanup(message,30); p=message.text.strip().split(maxsplit=1)
    if len(p)!=2 or p[0] not in {"primary","success","danger"}: await message.answer("Use: <code>primary 6041705726206808304</code>",parse_mode="HTML"); return
    d=await state.get_data(); conn=sqlite3.connect("bot.db", timeout=30); conn.execute("UPDATE store_subcategories SET button_style=?,sticker_id=? WHERE id=?",(p[0],"" if p[1]=="-" else p[1],d["store_sub_id"])); conn.commit(); conn.close(); await state.clear(); await message.answer("<b>Subcategory style updated.</b>",parse_mode="HTML")


@dp.callback_query(F.data.startswith("adm_sub_delete_"))
async def cb_admin_sub_delete_confirm(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    sid=callback.data.replace("adm_sub_delete_","",1)
    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True); return
    await callback.answer()
    _,key,name,_,_,_,_=sub
    await safe_edit(
        callback,
        "⚠️ <b>Delete Subcategory</b>\n\n"
        f"<b>{html.escape(name)}</b> and all accounts inside it will be deleted.\n\n"
        "<i>This cannot be undone.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="YES, DELETE",callback_data=f"adm_sub_delete_yes_{sid}",style="danger"),
            InlineKeyboardButton(text="Cancel",callback_data=f"adm_sub_{sid}",style="primary",icon_custom_emoji_id=BACK_EMOJI_ID)
        ]])
    )


@dp.callback_query(F.data.startswith("adm_sub_delete_yes_"))
async def cb_admin_sub_delete(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    sid=callback.data.replace("adm_sub_delete_yes_","",1)
    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True); return
    key=sub[1]
    account_rows=[]
    conn=sqlite3.connect("bot.db",timeout=30)
    try:
        account_rows=conn.execute("SELECT id FROM accounts WHERE subcategory_id=?",(sid,)).fetchall()
        conn.execute("DELETE FROM accounts WHERE subcategory_id=?",(sid,))
        conn.execute("DELETE FROM store_subcategories WHERE id=?",(sid,))
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logging.exception("Subcategory deletion failed")
        await callback.answer("Could not delete subcategory.",show_alert=True)
        return
    finally:
        conn.close()

    for (account_id,) in account_rows:
        try:
            delete_account_credentials(str(account_id))
        except Exception:
            logging.exception("Could not remove credentials for deleted account %s",account_id)

    await callback.answer("Subcategory deleted.")
    # Re-render parent category with one panel.
    fake = callback
    fake.data = f"adm_cat_{key}"
    await cb_admin_cat(fake)


@dp.callback_query(F.data.startswith("adm_sub_toggle_"))
async def cb_admin_sub_toggle(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True); return
    sid=callback.data.replace("adm_sub_toggle_","",1)
    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True); return
    new_enabled=0 if int(sub[6]) else 1
    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        conn.execute("UPDATE store_subcategories SET enabled=? WHERE id=?",(new_enabled,sid))
        conn.commit()
    finally:
        conn.close()
    await callback.answer("Subcategory enabled." if new_enabled else "Subcategory disabled.")
    await cb_admin_sub(callback)

@dp.callback_query(F.data.startswith("adm_sub_add_"))
async def cb_admin_sub_add_duplicate(callback:types.CallbackQuery):
    # Kept unreachable intentionally; the concrete handler above is registered first.
    return

@dp.callback_query(F.data.startswith("adm_sub_"))
async def cb_admin_sub(callback:types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return

    sid=callback.data.replace("adm_sub_","",1)
    if sid == "add" or sid.startswith(("style_","toggle_","delete_")):
        return

    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True)
        return

    await callback.answer()
    _,key,name,style,sticker,order,enabled=sub
    cat=store_category(key)

    conn=sqlite3.connect("bot.db", timeout=30)
    try:
        account_rows=conn.execute(
            "SELECT id,price FROM accounts WHERE subcategory_id=? AND stock_count>0 ORDER BY rowid ASC",
            (sid,)
        ).fetchall()
    finally:
        conn.close()

    rows=[
        [
            InlineKeyboardButton(
                text="Add Account",
                callback_data=f"adm_account_sub_{sid}",
                style="success"
            ),
            InlineKeyboardButton(
                text=("Disable" if enabled else "Enable"),
                callback_data=f"adm_sub_toggle_{sid}",
                style="primary"
            )
        ],
        [
            InlineKeyboardButton(
                text="Edit Style",
                callback_data=f"adm_sub_style_{sid}",
                style="primary"
            ),
            InlineKeyboardButton(
                text="Delete",
                callback_data=f"adm_sub_delete_{sid}",
                style="danger"
            )
        ]
    ]

    account_buttons=[
        InlineKeyboardButton(
            text=f"Account {i+1} • ${float(price):.2f}",
            callback_data=f"adm_account_view_{pid}",
            style="primary"
        )
        for i,(pid,price) in enumerate(account_rows)
    ]
    rows += [account_buttons[i:i+2] for i in range(0,len(account_buttons),2)]

    rows.append([
        InlineKeyboardButton(
            text="Back to Category",
            callback_data=f"adm_cat_{key}",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        f"📂 <b>{html.escape(cat[1] if cat else key)} → {html.escape(name)}</b>\n\n"
        f"Status: <b>{'Enabled' if enabled else 'Disabled'}</b>\n"
        f"Available accounts: <b>{len(account_rows)}</b>\n\n"
        "<i>Each account is one stock unit. Add as many as you need.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


# --- INDIVIDUAL ACCOUNT STOCK MANAGEMENT ---
@dp.callback_query(F.data.startswith("adm_account_view_"))
async def cb_admin_account_view(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    account_id = callback.data.replace("adm_account_view_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT a.id, a.category, a.title, a.price, a.stock_count, "
            "COALESCE(s.name,''), COALESCE(a.subcategory_id,'') "
            "FROM accounts a "
            "LEFT JOIN store_subcategories s ON s.id=a.subcategory_id "
            "WHERE a.id=?",
            (account_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        await callback.answer("Account not found.", show_alert=True)
        return

    acc_id, category, title, price, stock_count, sub_name, sub_id = row
    location = sub_name or "Category stock"

    await callback.answer()
    await safe_edit(
        callback,
        "👤 <b>Account Stock</b>\n\n"
        f"Account ID: <code>{html.escape(str(acc_id))}</code>\n"
        f"Category: <b>{html.escape(str(category or 'Account'))}</b>\n"
        f"Group: <b>{html.escape(str(location))}</b>\n"
        f"Price: <b>${float(price or 0):.2f}</b>\n"
        f"Stock units: <b>{int(stock_count or 0)}</b>\n\n"
        "<i>Credentials are kept in the encrypted vault and are not shown here.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Delete Account",
                    callback_data=f"adm_account_delete_{account_id}",
                    style="danger"
                )
            ],
            [
                InlineKeyboardButton(
                    text="Back to Stock",
                    callback_data=(f"adm_sub_{sub_id}" if sub_id else (f"adm_cat_{category_key_by_name(category)}" if category_key_by_name(category) else "admin_store")),
                    style="primary",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ],
            [
                InlineKeyboardButton(
                    text="Admin Panel",
                    callback_data="admin_panel",
                    style="danger",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.regexp(r"^adm_account_delete_(?!yes_).+$"))
async def cb_admin_account_delete_confirm(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    account_id = callback.data.replace("adm_account_delete_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT id, category, title, price, COALESCE(subcategory_id,'') "
            "FROM accounts WHERE id=?",
            (account_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        await callback.answer("Account not found.", show_alert=True)
        return

    _, category, title, price, sub_id = row

    await callback.answer()
    await safe_edit(
        callback,
        "⚠️ <b>Delete Account Stock</b>\n\n"
        f"Category: <b>{html.escape(str(category or 'Account'))}</b>\n"
        f"Group: <b>{html.escape(str(title or 'Account'))}</b>\n"
        f"Price: <b>${float(price or 0):.2f}</b>\n\n"
        "<b>This will permanently remove this account from stock and "
        "delete its encrypted credential record.</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="YES, DELETE",
                    callback_data=f"adm_account_delete_yes_{account_id}",
                    style="danger"
                ),
                InlineKeyboardButton(
                    text="Cancel",
                    callback_data=f"adm_account_view_{account_id}",
                    style="primary",
                    icon_custom_emoji_id=BACK_EMOJI_ID
                )
            ]
        ])
    )


@dp.callback_query(F.data.startswith("adm_account_delete_yes_"))
async def cb_admin_account_delete(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    account_id = callback.data.replace("adm_account_delete_yes_", "", 1)

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        row = conn.execute(
            "SELECT id, category, COALESCE(subcategory_id,'') "
            "FROM accounts WHERE id=?",
            (account_id,)
        ).fetchone()

        if not row:
            await callback.answer("Account not found.", show_alert=True)
            return

        _, category, sub_id = row

        cur = conn.execute(
            "DELETE FROM accounts WHERE id=?",
            (account_id,)
        )
        if cur.rowcount != 1:
            conn.rollback()
            await callback.answer(
                "Account could not be deleted.",
                show_alert=True
            )
            return

        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        logging.exception("Admin account deletion failed")
        await callback.answer(
            "Account deletion failed.",
            show_alert=True
        )
        return
    finally:
        conn.close()

    # The database row is the source of truth for stock. Remove the matching
    # encrypted record separately; failure here does not restore deleted stock.
    try:
        delete_account_credentials(str(account_id))
    except Exception:
        logging.exception(
            "Could not delete encrypted credentials for removed account %s",
            account_id
        )

    await callback.answer("Account deleted.")

    if sub_id:
        # Refresh the parent subcategory panel through its existing rendering
        # path, but preserve the real callback message.
        data = dict(
            id=callback.id,
            from_user=callback.from_user,
            chat_instance=callback.chat_instance,
            data=f"adm_sub_{sub_id}",
            message=callback.message,
        )
        refresh_callback = types.CallbackQuery.model_validate(data)
        await cb_admin_sub(refresh_callback)
        return

    cat_key = category_key_by_name(category)
    if cat_key:
        data = dict(
            id=callback.id,
            from_user=callback.from_user,
            chat_instance=callback.chat_instance,
            data=f"adm_cat_{cat_key}",
            message=callback.message,
        )
        refresh_callback = types.CallbackQuery.model_validate(data)
        await cb_admin_cat(refresh_callback)
    else:
        await cb_admin_store(callback)


@dp.callback_query(F.data == "adm_stock_add")
async def cb_admin_stock_add(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.", show_alert=True)
        return

    await callback.answer()
    cats=store_categories(enabled_only=True)
    buttons=[
        InlineKeyboardButton(
            text=name,
            callback_data=f"adm_account_cat_{key}",
            style=safe_style(style),
            icon_custom_emoji_id=(sticker or DEFAULT_CATEGORY_STICKERS.get(key) or None)
        )
        for key,name,style,sticker,_,_ in cats
    ]
    rows=[buttons[i:i+2] for i in range(0,len(buttons),2)]
    rows.append([
        InlineKeyboardButton(
            text="Back",
            callback_data="admin_store",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])
    await safe_edit(
        callback,
        rich_emoji("5042302287087666158", "➕") + " <b>Add Account Stock</b>\n\n"
        "<i>Choose a category first.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data.startswith("adm_account_cat_"))
async def cb_admin_account_category(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return

    key=callback.data.replace("adm_account_cat_","",1)
    cat=store_category(key)
    if not cat:
        await callback.answer("Category not found.",show_alert=True)
        return

    await callback.answer()
    subs=store_subs(key,enabled_only=True)

    if not subs:
        await start_clean_account_wizard(callback,state,key,None,cat[1])
        return

    buttons=[
        InlineKeyboardButton(
            text=sname,
            callback_data=f"adm_account_sub_{sid}",
            style=safe_style(sstyle),
            icon_custom_emoji_id=ssticker or None
        )
        for sid,sname,sstyle,ssticker,_,_ in subs
    ]
    rows=[buttons[i:i+2] for i in range(0,len(buttons),2)]
    rows.append([
        InlineKeyboardButton(
            text="Account directly in category",
            callback_data=f"adm_account_subcat_{key}",
            style="primary"
        )
    ])
    rows.append([
        InlineKeyboardButton(
            text="Back",
            callback_data=f"adm_cat_{key}",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        rich_emoji("5042302287087666158", "➕") + " <b>Add Account Stock</b>\n\n"
        f"<b>Category:</b> {html.escape(cat[1])}\n\n"
        "<i>Select the subcategory.</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )


@dp.callback_query(F.data.startswith("adm_account_sub_"))
async def cb_admin_account_subcategory(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return

    sid=callback.data.replace("adm_account_sub_","",1)
    sub=store_sub(sid)
    if not sub:
        await callback.answer("Subcategory not found.",show_alert=True)
        return

    await start_clean_account_wizard(callback,state,sub[1],sid,sub[2])


@dp.callback_query(F.data.startswith("adm_account_subcat_"))
async def cb_admin_account_direct_category(callback:types.CallbackQuery,state:FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("Unauthorized access.",show_alert=True)
        return
    key=callback.data.replace("adm_account_subcat_","",1)
    cat=store_category(key)
    if not cat:
        await callback.answer("Category not found.",show_alert=True)
        return
    await start_clean_account_wizard(callback,state,key,None,cat[1])


async def start_clean_account_wizard(
    callback:types.CallbackQuery,
    state:FSMContext,
    category_key:str,
    subcategory_id:str|None,
    bucket_name:str
):
    cat=store_category(category_key)
    if not cat:
        await callback.answer("Category not found.",show_alert=True)
        return

    await callback.answer()
    await state.set_state(AdminState.waiting_for_product_details)
    await state.update_data(
        account_category_key=category_key,
        account_subcategory_id=subcategory_id,
        account_bucket_name=bucket_name,
        account_wizard_step="price"
    )

    await safe_edit(
        callback,
        "➕ <b>Add Account</b>\n\n"
        f"<b>{html.escape(cat[1])}</b>  →  <b>{html.escape(bucket_name)}</b>\n\n"
        "<b>Step 1/6 — Price</b>\n"
        "Enter the selling price in USD.\n\n"
        "Example: <code>15</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(
                text="Cancel",
                callback_data=(f"adm_sub_{subcategory_id}" if subcategory_id else f"adm_cat_{category_key}"),
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )
        ]])
    )


@dp.message(AdminState.waiting_for_product_details, F.text)
async def admin_product_wizard_input(message:types.Message,state:FSMContext):
    if not is_admin(message.from_user.id):
        return

    schedule_user_message_cleanup(message,30)
    data=await state.get_data()
    step=data.get("account_wizard_step","price")
    value=(message.text or "").strip()

    if not value:
        await message.answer(
            "⚠️ <b>Input Required</b>\n\nPlease enter a value.",
            parse_mode="HTML"
        )
        return

    prompts={
        "username":("👤","Username","Enter the account username."),
        "password":("🔐","Password","Enter the account password."),
        "email":("📧","Email","Enter the account email."),
        "email_password":("🔑","Email Password","Enter the email password."),
        "two_fa":("🛡️","2FA","Enter the account 2FA value."),
    }

    if step=="price":
        try:
            price=float(value)
            if price<=0:
                raise ValueError
        except ValueError:
            await message.answer(
                "⚠️ <b>Invalid Price</b>\n\nEnter a valid USD price.\nExample: <code>15</code>",
                parse_mode="HTML"
            )
            return
        await state.update_data(account_price=price,account_wizard_step="username")
        await message.answer(
            "👤 <b>Add Account</b>\n\n<b>Step 2/6 — Username</b>\nEnter the account username.",
            parse_mode="HTML"
        )
        return

    if step in prompts:
        emoji,title,body=prompts[step]
        if step=="username":
            await state.update_data(account_username=value,account_wizard_step="password")
            nxt=("🔐 <b>Add Account</b>\n\n<b>Step 3/6 — Password</b>\nEnter the account password.")
        elif step=="password":
            await state.update_data(account_password=value,account_wizard_step="email")
            nxt=("📧 <b>Add Account</b>\n\n<b>Step 4/6 — Email</b>\nEnter the account email.")
        elif step=="email":
            await state.update_data(account_email=value,account_wizard_step="email_password")
            nxt=("🔑 <b>Add Account</b>\n\n<b>Step 5/6 — Email Password</b>\nEnter the email password.")
        elif step=="email_password":
            await state.update_data(account_email_password=value,account_wizard_step="two_fa")
            nxt=("🛡️ <b>Add Account</b>\n\n<b>Step 6/6 — 2FA</b>\nEnter the account 2FA value.")
        else:
            # Final field.
            category_key=data.get("account_category_key")
            sub_id=data.get("account_subcategory_id")
            cat=store_category(category_key) if category_key else None
            if not cat:
                await state.clear()
                await message.answer("Category not found.",parse_mode="HTML")
                return

            price=float(data.get("account_price",0))
            bucket=str(data.get("account_bucket_name") or cat[1])
            credentials={
                "username":str(data.get("account_username","")),
                "password":str(data.get("account_password","")),
                "email":str(data.get("account_email","")),
                "email_password":str(data.get("account_email_password","")),
                "two_fa_code":value,
            }

            conn=sqlite3.connect("bot.db",timeout=30)
            try:
                id_info=conn.execute("PRAGMA table_info(accounts)").fetchall()
                id_col=next((r for r in id_info if r[1]=="id"),None)
                id_type=(id_col[2] or "").upper() if id_col else ""
                integer_id=bool(id_col and id_col[5]==1 and "INT" in id_type)

                if integer_id:
                    conn.execute(
                        "INSERT INTO accounts(category,title,price,stock_count,credentials_format,subcategory_id) "
                        "VALUES(?,?,?,?,?,?)",
                        (cat[1],bucket,price,1,"secure-vault",sub_id)
                    )
                    account_id=conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                else:
                    account_id=f"ACC-{int(datetime.now().timestamp()*1000)}"
                    conn.execute(
                        "INSERT INTO accounts(id,category,title,price,stock_count,credentials_format,subcategory_id) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (account_id,cat[1],bucket,price,1,"secure-vault",sub_id)
                    )
                conn.commit()
            except sqlite3.Error:
                conn.rollback()
                logging.exception("Account stock creation failed")
                await state.clear()
                await message.answer(
                    "❌ <b>Account could not be added.</b>\n\nDatabase rejected the account.",
                    parse_mode="HTML"
                )
                return
            finally:
                conn.close()

            try:
                save_account_credentials(str(account_id),credentials)
            except Exception:
                logging.exception("Encrypted credential vault write failed")
                conn=sqlite3.connect("bot.db",timeout=30)
                try:
                    conn.execute("DELETE FROM accounts WHERE id=?",(account_id,))
                    conn.commit()
                finally:
                    conn.close()
                await state.clear()
                await message.answer(
                    "❌ <b>Account was not saved.</b>\n\nSecure credential storage failed.",
                    parse_mode="HTML"
                )
                return

            await state.clear()
            await message.answer(
                "✅ <b>Account Added</b>\n\n"
                f"Category: <b>{html.escape(cat[1])}</b>\n"
                f"Group: <b>{html.escape(bucket)}</b>\n"
                f"Price: <b>${price:.2f}</b>\n"
                f"Account ID: <code>{html.escape(str(account_id))}</code>\n\n"
                "<i>Available stock increased by 1.</i>",
                parse_mode="HTML"
            )
            return
        await message.answer(nxt,parse_mode="HTML")
        return

    await state.clear()
    await message.answer("The account-entry session expired.",parse_mode="HTML")



@dp.callback_query(F.data == "create_order")
async def cb_create_order(callback:types.CallbackQuery):
    await callback.answer(); await show_create_order(callback.message,edit=True,callback=callback)

async def show_create_order(msg_obj,edit=False,callback=None):
    cats=store_categories(enabled_only=True)
    text=(
        rich_emoji("5893224751119208859", "💎") + " "
        "<b>Select Account Category</b>\n\n"
        "<i>Select a category below to view available aged accounts.</i>"
    )

    category_buttons=[
        InlineKeyboardButton(
            text=name,
            callback_data=f"cat_{key}",
            style=safe_style(style),
            icon_custom_emoji_id=(sticker or DEFAULT_CATEGORY_STICKERS.get(key) or None)
        )
        for key,name,style,sticker,_,_ in cats
    ]

    # Two category buttons per row.
    rows=[
        category_buttons[i:i+2]
        for i in range(0,len(category_buttons),2)
    ]
    rows.append([
        InlineKeyboardButton(
            text="Back to Main Menu",
            callback_data="main_menu",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    kb=InlineKeyboardMarkup(inline_keyboard=rows)
    if edit and callback:
        await safe_edit(callback,text,reply_markup=kb)
    else:
        await msg_obj.answer(text,parse_mode="HTML",reply_markup=kb)

@dp.callback_query(F.data.startswith("cat_"))
async def cb_view_category(callback:types.CallbackQuery):
    await callback.answer(); key=callback.data.replace("cat_",""); cat=store_category(key)
    if not cat: await callback.answer("Category unavailable.",show_alert=True); return
    _,name,style,sticker,_,enabled=cat
    if not enabled: await callback.answer("Category unavailable.",show_alert=True); return
    subs=store_subs(key,enabled_only=True); rows=[]
    if subs:
        sub_buttons=[
            InlineKeyboardButton(
                text=sname,
                callback_data=f"sub_{sid}",
                style=safe_style(sstyle),
                icon_custom_emoji_id=(ssticker or None)
            )
            for sid,sname,sstyle,ssticker,_,_ in subs
        ]
        rows.extend(sub_buttons[i:i+2] for i in range(0,len(sub_buttons),2))
        text=(
            f"{rich_emoji(sticker or DEFAULT_CATEGORY_STICKERS.get(key) or '5893224751119208859', '📦')} "
            f"<b>{html.escape(name)}</b>\n\n"
            "<i>Select a subcategory.</i>"
        )
    else:
        conn=sqlite3.connect("bot.db", timeout=30)
        try: products=conn.execute("SELECT id,title,price,stock_count FROM accounts WHERE category=? AND stock_count>0 ORDER BY title",(name,)).fetchall()
        finally: conn.close()
        rows += [[InlineKeyboardButton(text=f"{title} — ${price:.2f} ({stock} left)",callback_data=f"buy_{pid}",style="primary")] for pid,title,price,stock in products]
        text=(
            f"{rich_emoji(sticker or DEFAULT_CATEGORY_STICKERS.get(key) or '5893224751119208859', '📦')} "
            f"<b>{html.escape(name)} Accounts</b>\n\n"
            "<i>Select an account below to purchase.</i>"
        )
        if not products:text += "\n\n<i>No stock available right now.</i>"
    rows.append([InlineKeyboardButton(text="Back to Categories",callback_data="create_order",style="danger",icon_custom_emoji_id=BACK_EMOJI_ID)])
    await safe_edit(callback,text,reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))

@dp.callback_query(F.data.startswith("sub_"))
async def cb_view_subcategory(callback: types.CallbackQuery):
    await callback.answer()
    sid = callback.data.replace("sub_", "", 1)
    sub = store_sub(sid)

    if not sub:
        await callback.answer("Subcategory unavailable.", show_alert=True)
        return

    _, category_key, sub_name, sub_style, sub_sticker, _, enabled = sub
    if not enabled:
        await callback.answer("Subcategory unavailable.", show_alert=True)
        return

    cat = store_category(category_key)
    if not cat:
        await callback.answer("Category unavailable.", show_alert=True)
        return

    conn = sqlite3.connect("bot.db", timeout=30)
    try:
        # One visible purchase button: the next account in this subcategory.
        account = conn.execute(
            "SELECT id, price FROM accounts "
            "WHERE subcategory_id=? AND stock_count>0 "
            "ORDER BY rowid ASC LIMIT 1",
            (sid,)
        ).fetchone()

        total = conn.execute(
            "SELECT COUNT(*) FROM accounts "
            "WHERE subcategory_id=? AND stock_count>0",
            (sid,)
        ).fetchone()[0] or 0
    finally:
        conn.close()

    rows = []
    if account:
        account_id, price = account
        rows.append([
            InlineKeyboardButton(
                text=f"Buy Account — ${price:.2f}",
                callback_data=f"buy_{account_id}",
                style="primary"
            )
        ])
        text_msg = (
            f"{rich_emoji(sub_sticker or '5893224751119208859', '📦')} "
            f"<b>{html.escape(cat[1])} • {html.escape(sub_name)}</b>\n\n"
            f"<i>Available accounts: {total}</i>\n\n"
            "<b>Next account:</b> ready for purchase."
        )
    else:
        text_msg = (
            f"{rich_emoji(sub_sticker or '5893224751119208859', '📦')} "
            f"<b>{html.escape(cat[1])} • {html.escape(sub_name)}</b>\n\n"
            "<i>No account is available right now.</i>"
        )

    rows.append([
        InlineKeyboardButton(
            text="Back",
            callback_data=f"cat_{category_key}",
            style="danger",
            icon_custom_emoji_id=BACK_EMOJI_ID
        )
    ])

    await safe_edit(
        callback,
        text_msg,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows)
    )



@dp.callback_query(F.data.startswith("buy_"))
async def cb_buy_item(callback: types.CallbackQuery):
    await callback.answer()
    item_id = callback.data.replace("buy_", "", 1)
    user_id = str(callback.from_user.id)

    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()

    try:
        # Locking is handled by the write transaction below. First fetch the
        # exact next account requested by this button.
        cursor.execute(
            "SELECT a.id, a.price, a.stock_count, a.category, "
            "COALESCE(s.name,''), a.title, COALESCE(a.subcategory_id,'') "
            "FROM accounts a "
            "LEFT JOIN store_subcategories s ON s.id=a.subcategory_id "
            "WHERE a.id=?",
            (item_id,)
        )
        acc = cursor.fetchone()

        if not acc or int(acc[2] or 0) <= 0:
            conn.close()
            await callback.answer("This account is no longer available.", show_alert=True)
            return

        acc_id, price, stock, category, subcategory_name, title, subcategory_id = acc

        cursor.execute(
            "SELECT balance, total_spent FROM users WHERE telegram_id=?",
            (user_id,)
        )
        urow = cursor.fetchone()
        if not urow:
            conn.close()
            await callback.answer("User account not found.", show_alert=True)
            return

        b_before = float(urow[0] or 0)
        t_spent = float(urow[1] or 0)

        if b_before < float(price):
            conn.close()
            shortfall = float(price) - b_before
            await safe_edit(
                callback,
                "❌ <b>Insufficient Balance</b>\n\n"
                f"Required: <b>${float(price):.2f}</b>\n"
                f"Available: <b>${b_before:.2f}</b>\n"
                f"Shortfall: <b>${shortfall:.2f}</b>",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(
                        text="Add Balance",
                        callback_data="add_balance",
                        style="primary"
                    )],
                    [InlineKeyboardButton(
                        text="Back",
                        callback_data=f"sub_{subcategory_id}",
                        style="danger",
                        icon_custom_emoji_id=BACK_EMOJI_ID
                    )]
                ])
            )
            return

        # Read credentials before removing the inventory row.
        secure_credentials = get_account_credentials(str(acc_id))
        if not secure_credentials:
            conn.close()
            await callback.answer(
                "This account has no secure credential record. Contact support.",
                show_alert=True
            )
            return

        b_after = b_before - float(price)
        new_spent = t_spent + float(price)
        ord_id = f"ORD-{int(datetime.now().timestamp()*1000)}"

        # The account row is the stock unit. A successful purchase removes the
        # row completely; therefore the next account in the same subcategory
        # becomes the next visible purchase automatically.
        cursor.execute(
            "UPDATE users SET balance=?, total_spent=? WHERE telegram_id=?",
            (b_after, new_spent, user_id)
        )
        cursor.execute(
            "DELETE FROM accounts WHERE id=? AND stock_count>0",
            (item_id,)
        )

        if cursor.rowcount != 1:
            conn.rollback()
            conn.close()
            await callback.answer(
                "That account was already purchased. Refresh the category.",
                show_alert=True
            )
            return

        order_title = subcategory_name or title or "Account"
        cursor.execute(
            "INSERT INTO orders (id, telegram_id, category, item_title, price, status) "
            "VALUES (?, ?, ?, ?, ?, 'completed')",
            (
                ord_id,
                user_id,
                category or "Account",
                order_title,
                float(price)
            )
        )

        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        logging.exception("Purchase transaction failed")
        await callback.answer("Purchase failed. Nothing was charged.", show_alert=True)
        return
    finally:
        conn.close()

    log_transaction(
        user_id,
        "purchase",
        f"🛒 {order_title}",
        -float(price),
        b_before,
        b_after,
        ord_id
    )

    delivery_ok = await deliver_credentials_privately(
        user_id=int(user_id),
        item_title=order_title,
        order_id=ord_id,
        credentials=secure_credentials
    )

    # Publish only non-sensitive purchase metadata to the configured channel.
    # OTP, passwords, usernames, user IDs and private credentials are excluded.
    announcement_ok = await publish_purchase_announcement(
        category=category or "Account",
        subcategory=order_title,
        price=float(price),
        order_id=ord_id,
    )
    if not announcement_ok:
        logging.info(
            "Purchase channel announcement skipped/failed for order %s",
            ord_id
        )

    if delivery_ok:
        try:
            delete_account_credentials(str(acc_id))
        except Exception:
            logging.exception(
                "Could not remove sold account credentials from encrypted vault: %s",
                acc_id
            )

    await safe_edit(
        callback,
        rich_emoji("5893473283696759404", "✅") + " <b>Purchase Successful</b>\n\n"
        + rich_emoji("5893048571560726748", "🧾")
        + f" <b>Order ID:</b> <code>{html.escape(str(ord_id))}</code>\n"
        + rich_emoji("6039641775377748623", "📦")
        + f" <b>Category:</b> <b>{html.escape(str(category or 'Account'))}</b>\n"
        + rich_emoji("5893168654551355607", "🏷️")
        + f" <b>Account Group:</b> <b>{html.escape(str(order_title))}</b>\n"
        + rich_emoji("5893048571560726748", "💳")
        + f" <b>Price:</b> <b>${float(price):.2f}</b>\n"
        + rich_emoji("5224257782013769471", "💰")
        + f" <b>Remaining Balance:</b> <b>${b_after:.2f}</b>\n\n"
        + (
            rich_emoji("6041705726206808304", "🔐")
            + " <b>Account details were sent privately.</b>\n"
            + "Save them now. The delivery message will be deleted after 5 minutes."
            if delivery_ok else
            rich_emoji("5895444149699612825", "⚠️")
            + " <b>Purchase completed, but delivery failed.</b>\n"
            + "Contact support with your Order ID."
        ),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(
                text="View Orders",
                callback_data="orders",
                style="primary"
            )],
            [InlineKeyboardButton(
                text="Main Menu",
                callback_data="main_menu",
                style="danger",
                icon_custom_emoji_id=BACK_EMOJI_ID
            )]
        ])
    )


@dp.callback_query(F.data.in_({"orders", "my_orders"}))
async def cb_my_orders(callback: types.CallbackQuery):
    await callback.answer()
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT id, item_title, price, status, created_at FROM orders WHERE telegram_id = ? ORDER BY created_at DESC", (str(callback.from_user.id),))
    orders = cursor.fetchall()
    conn.close()

    if not orders:
        await safe_edit(
            callback,
            "<tg-emoji emoji-id='5893382531037794941'>📦</tg-emoji> <b>No Order History Available</b>" + chr(10) + chr(10) + "<i>You haven't purchased anything yet.</i>" + chr(10) + chr(10) + "<b>Browse the store and make your first purchase.</b>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="Browse Store & Buy Accounts", callback_data="create_order", style="primary", icon_custom_emoji_id=BACK_EMOJI_ID)],
                [InlineKeyboardButton(text="Back to Main Menu", callback_data="main_menu", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
            ])
        )
        return

    lines = ["📜 <b>Your Order History:</b>\n"]
    for o_id, title, price, status, dt in orders:
        lines.append(f"• <code>#{o_id}</code> — <b>{title}</b> (${price:.2f}) [{status.upper()}]\n  <i>{dt}</i>")
    
    lines.append("\nTap below to return:")
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="Main Menu", callback_data="main_menu", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]])
    await safe_edit(callback, "\n".join(lines), reply_markup=kb)

# --- ADMIN ADD STOCK COMMAND ---
@dp.message(Command("addstock"))
async def cmd_add_stock(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.reply("Unauthorized access. Admin only.")
        return
    parts = message.text.replace("/addstock", "").strip().split("|")
    if len(parts) < 5:
        await message.reply(
            "⚠️ <b>Usage:</b>\n<code>/addstock Instagram | 2020 Account | 19.99 | 10 | user:pass:2fa</code>",
            parse_mode="HTML"
        )
        return
    cat, title, price_s, stock_s, creds = [p.strip() for p in parts[:5]]
    acc_id = f"ACC-{int(datetime.now().timestamp()*1000)}"
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO accounts (id, category, title, price, stock_count, credentials_format)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (acc_id, cat, title, float(price_s), int(stock_s), creds))
    conn.commit()
    conn.close()
    await message.reply(f"✅ <b>Account Stock Added!</b>\n• ID: <code>{acc_id}</code>\n• Category: {cat}\n• Title: {title}\n• Price: ₹{price_s}\n• Stock: {stock_s}", parse_mode="HTML")

@dp.callback_query(F.data == "profile")
async def cb_profile(callback: types.CallbackQuery):
    await callback.answer()
    conn = sqlite3.connect("bot.db", timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT balance, total_spent, joined_at FROM users WHERE telegram_id = ?", (str(callback.from_user.id),))
    row = cursor.fetchone()
    bal = row[0] if row and row[0] is not None else 0.0
    spent = row[1] if row and row[1] is not None else 0.0
    joined = row[2] if row and row[2] else "Recently"
    conn.close()

    text = (
        "<tg-emoji emoji-id='5033259521208747582'>👤</tg-emoji> "
        "<b>User Profile</b>" + chr(10) + chr(10)
        + f"• Telegram ID: {callback.from_user.id}" + chr(10) + chr(10)
        + f"• Username: @{callback.from_user.username or 'User'}" + chr(10) + chr(10)
        + f"• Wallet Balance: ${bal:.2f}" + chr(10) + chr(10)
        + f"• Total Spent: ${spent:.2f}" + chr(10) + chr(10)
        + f"• Member Since: {joined}"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Wallet", callback_data="wallet", style="primary", icon_custom_emoji_id="5893473283696759404"), InlineKeyboardButton(text="Orders", callback_data="my_orders", style="primary", icon_custom_emoji_id=ORDERS_EMOJI_ID)],
        [InlineKeyboardButton(text="Main Menu", callback_data="main_menu", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
    ])
    await safe_edit(callback, text, reply_markup=kb)

@dp.callback_query(F.data == "support")
async def cb_support(callback: types.CallbackQuery):
    await callback.answer()
    text = (
        "<tg-emoji emoji-id='5031035625797584499'>🛟</tg-emoji> "
        "<b>Support &amp; Help Center</b>" + chr(10) + chr(10)
        + "Need assistance with your account purchase or wallet top-up?"
        + chr(10) + chr(10)
        + "• Primary Admin: @wadeds" + chr(10)
        + "• Admin Chat ID: 8860215592" + chr(10)
        + "• Support Hours: 24/7 Live Support"
        + chr(10) + chr(10)
        + "Click an admin button below to open a direct Telegram chat for instant help!"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Contact Admin", url="https://t.me/wadeds", style="primary", icon_custom_emoji_id=CONTACT_EMOJI_ID)],
        [InlineKeyboardButton(text="Back to Main Menu", callback_data="main_menu", style="danger", icon_custom_emoji_id=BACK_EMOJI_ID)]
    ])
    await safe_edit(callback, text, reply_markup=kb)



# --- FORWARDED MESSAGE & MULTI-STICKER / CUSTOM EMOJI EXTRACTOR ---
@dp.callback_query(F.data == "main_menu")
async def cb_main_menu(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()

    if not is_admin(callback.from_user.id):
        if not await user_has_joined_required_channels(callback.from_user.id):
            await state.clear()
            await show_force_join_for_callback(callback)
            return

    await state.clear()

    welcome_text = get_welcome_text()
    keyboard = get_main_menu(callback.from_user.id)
    image_path = "images/dash.png"

    try:
        await callback.message.delete()
    except Exception:
        pass

    if os.path.exists(image_path):
        await callback.message.answer_photo(
            photo=FSInputFile(image_path),
            caption=welcome_text,
            parse_mode="HTML",
            reply_markup=keyboard
        )
    else:
        await callback.message.answer(
            welcome_text,
            parse_mode="HTML",
            reply_markup=keyboard
        )


@dp.message()
async def handle_unrecognized_message(message: types.Message):
    """Handle unsupported/unknown messages without exposing internal IDs."""
    if message.from_user:
        conn = sqlite3.connect("bot.db", timeout=30)
        try:
            exists = conn.execute(
                "SELECT 1 FROM banned_users WHERE telegram_id=?",
                (str(message.from_user.id),)
            ).fetchone()
        except sqlite3.Error:
            exists = None
        finally:
            conn.close()

        if exists:
            return

    await message.reply(
        rich_emoji("5983568653751160844", "ℹ️")
        + " <b>Use /start to open the main menu.</b>",
        parse_mode="HTML"
    )

if __name__ == "__main__":
    import asyncio
    if not TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is not set. Set it before starting the bot.")
    print("Bot is starting...")
    asyncio.run(dp.start_polling(bot))
