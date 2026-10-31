#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JUBYER JWT GENERATOR BOT
------------------------
Telegram বট: JSON ফাইল (UID + Password) আপলোড -> API থেকে JWT Token সংগ্রহ -> token_bd.json এ সংরক্ষণ।

Python 3.11 | python-telegram-bot 22.x | Hosting: Wispbyte
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx
from telegram import BotCommand, Update
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ─────────────────────────────────────────────────────────────
# কনফিগারেশন (Environment Variables)
# ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> None:
    """ঐচ্ছিক .env ফাইল পড়ে (Environment Variable আগে থেকে সেট থাকলে সেটাই থাকবে)।"""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(BASE_DIR / ".env")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def _parse_admin_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for part in re.split(r"[,\s]+", raw.strip()):
        if part.isdigit():
            ids.add(int(part))
    return ids


BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = _parse_admin_ids(os.getenv("ADMIN_ID", ""))
API_URL = os.getenv("API_URL", "https://jwt-proff.up.railway.app/token").strip()
DEFAULT_REGION = os.getenv("DEFAULT_REGION", "BD").strip().upper() or "BD"
MAX_ACCOUNTS = _env_int("MAX_ACCOUNTS", 500)
CONCURRENCY = max(1, _env_int("CONCURRENCY", 5))
API_TIMEOUT = max(5, _env_int("API_TIMEOUT", 30))
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
DELETE_UPLOADED = os.getenv("DELETE_UPLOADED", "true").strip().lower() in ("1", "true", "yes", "on")
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

TOKEN_FILE = DATA_DIR / "token_bd.json"
FAILED_FILE = DATA_DIR / "failed_bd.json"
USERS_FILE = DATA_DIR / "users.json"

# ─────────────────────────────────────────────────────────────
# লগিং (Password / Token কখনো লগে যাবে না)
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
# httpx URL লগ করে (যার মধ্যে password থাকে) – তাই বন্ধ রাখা হলো
for _noisy in ("httpx", "httpcore", "telegram", "hpack"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("jubyer-jwt-bot")


def scrub(text: str, *secrets: str) -> str:
    """টেক্সট থেকে গোপন তথ্য মুছে ফেলে।"""
    for secret in secrets + (BOT_TOKEN,):
        if secret:
            text = text.replace(secret, "***")
    return text


# ─────────────────────────────────────────────────────────────
# স্টোরেজ (users.json + token_bd.json)
# ─────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _write_json(path: Path, data: Any) -> None:
    """Atomic write: আগে temp ফাইলে লিখে তারপর replace করে।"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_token_entries() -> list[dict[str, str]]:
    """
    token_bd.json পড়ে [{"uid", "token", "region"}, ...] তালিকা ফেরত দেয়।
    পুরোনো ফরম্যাট ({"success": [...], "failed": [...]}) থাকলেও সেটি নতুন ফরম্যাটে রূপান্তর করে।
    একই UID থাকলে একটিই রাখা হয়।
    """
    raw = _read_json(TOKEN_FILE, [])
    if isinstance(raw, dict):  # পুরোনো ফরম্যাট
        raw = raw.get("success", [])
    entries: dict[str, dict[str, str]] = {}
    if isinstance(raw, list):
        for e in raw:
            if isinstance(e, dict) and e.get("uid") and e.get("token"):
                uid = str(e["uid"])
                entries[uid] = {
                    "uid": uid,
                    "token": str(e["token"]),
                    "region": str(e.get("region") or DEFAULT_REGION),
                }
    return list(entries.values())


class Store:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        raw = _read_json(USERS_FILE, {"users": []})
        self.users: set[int] = {
            int(x) for x in raw.get("users", []) if str(x).isdigit()
        }

    # ── Users ──
    def _save_users(self) -> None:
        _write_json(USERS_FILE, {"users": sorted(self.users)})

    async def add_user(self, user_id: int) -> bool:
        async with self.lock:
            if user_id in self.users or user_id in ADMIN_IDS:
                return False
            self.users.add(user_id)
            self._save_users()
            return True

    async def remove_user(self, user_id: int) -> bool:
        async with self.lock:
            if user_id not in self.users:
                return False
            self.users.discard(user_id)
            self._save_users()
            return True

    # ── Tokens ──
    async def save_results(self, results: list[dict[str, Any]]) -> None:
        """
        token_bd.json গঠন (শুধু সফল অ্যাকাউন্ট):
        [
          {"uid": "8381652847", "token": "JWT_TOKEN_HERE", "region": "BD"},
          ...
        ]
        - একই UID একবারই থাকে; নতুন Token তৈরি হলে আগের UID-র Token আপডেট হয়।
        - ব্যর্থ অ্যাকাউন্ট আলাদা failed_bd.json ফাইলে থাকে (token ফাইলে নয়)।
        - সর্বশেষ ফলাফলই কার্যকর: সফল হলে failed থেকে বাদ, ব্যর্থ হলে token ফাইল থেকে বাদ।
        """
        async with self.lock:
            success = {e["uid"]: e for e in load_token_entries()}

            # পুরোনো ফরম্যাটের failed তালিকা (থাকলে) + বর্তমান failed_bd.json
            raw_old = _read_json(TOKEN_FILE, [])
            legacy_failed = raw_old.get("failed", []) if isinstance(raw_old, dict) else []
            file_failed = _read_json(FAILED_FILE, [])
            failed: dict[str, dict[str, Any]] = {}
            for e in list(legacy_failed) + (file_failed if isinstance(file_failed, list) else []):
                if isinstance(e, dict) and e.get("uid"):
                    failed[str(e["uid"])] = {
                        "uid": str(e["uid"]),
                        "error": str(e.get("error", "")),
                        "failed_at": str(e.get("failed_at", "")),
                    }
            stamp = _now()

            for res in results:
                uid = str(res["uid"])
                if res["ok"]:
                    success[uid] = {
                        "uid": uid,
                        "token": res["token"],
                        "region": res["region"],
                    }
                    failed.pop(uid, None)
                else:
                    failed[uid] = {"uid": uid, "error": res["error"], "failed_at": stamp}
                    success.pop(uid, None)

            _write_json(TOKEN_FILE, list(success.values()))
            _write_json(FAILED_FILE, list(failed.values()))


store = Store()

# ─────────────────────────────────────────────────────────────
# JSON ফাইল পার্সিং (UID + Password)
# ─────────────────────────────────────────────────────────────
UID_KEYS = {"uid", "user_id", "userid", "guest_uid", "com.garena.msdk.guest_uid"}
PASS_KEYS = {
    "password",
    "pass",
    "pwd",
    "passwd",
    "guest_password",
    "com.garena.msdk.guest_password",
}


def _pick(d: dict[str, Any], keys: set[str]) -> str | None:
    for k, v in d.items():
        if str(k).lower() in keys and isinstance(v, (str, int)) and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
    return None


def _walk(obj: Any, out: list[tuple[str, str]], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, list):
        for item in obj:
            _walk(item, out, depth + 1)
    elif isinstance(obj, dict):
        uid, pw = _pick(obj, UID_KEYS), _pick(obj, PASS_KEYS)
        if uid and pw:
            out.append((uid, pw))
            return
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk(v, out, depth + 1)
            elif (
                isinstance(v, (str, int))
                and not isinstance(v, bool)
                and str(k).strip().isdigit()
                and str(v).strip()
            ):
                # {"UID": "PASSWORD"} ফরম্যাট
                out.append((str(k).strip(), str(v).strip()))


def parse_accounts(raw: bytes) -> list[tuple[str, str]]:
    """JSON বাইট থেকে (uid, password) তালিকা বের করে। ভুল হলে ValueError।"""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("ফাইলটি UTF-8 টেক্সট নয়। সঠিক JSON ফাইল দিন।")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON ফরম্যাট ভুল (লাইন {exc.lineno}, কলাম {exc.colno})।")

    found: list[tuple[str, str]] = []
    _walk(data, found)

    seen: set[str] = set()
    accounts: list[tuple[str, str]] = []
    for uid, pw in found:
        if uid not in seen:
            seen.add(uid)
            accounts.append((uid, pw))

    if not accounts:
        raise ValueError("ফাইলে কোনো UID ও Password পাওয়া যায়নি।")
    return accounts


# ─────────────────────────────────────────────────────────────
# API Integration
# ─────────────────────────────────────────────────────────────
JWT_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")
TOKEN_KEYS = {"token", "jwt", "access_token", "accesstoken", "jwt_token", "jwttoken"}
REGION_KEYS = {"region", "lock_region", "noti_region"}
ACCOUNT_KEYS = {"account_id", "accountid", "account_uid"}
ERROR_KEYS = {"error", "message", "msg", "detail", "reason"}


def find_first(
    obj: Any,
    keys: set[str],
    validator: Callable[[str], bool] | None = None,
    depth: int = 0,
) -> str | None:
    """নেস্টেড dict/list এ প্রথম মিলে যাওয়া key এর মান খোঁজে।"""
    if depth > 4:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v).strip()
                if s and (validator is None or validator(s)):
                    return s
        for v in obj.values():
            if isinstance(v, (dict, list)):
                r = find_first(v, keys, validator, depth + 1)
                if r:
                    return r
    elif isinstance(obj, list):
        for v in obj[:20]:
            if isinstance(v, (dict, list)):
                r = find_first(v, keys, validator, depth + 1)
                if r:
                    return r
    return None


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """JWT এর payload (signature যাচাই ছাড়া) পড়ে – শুধু region/account id বের করতে।"""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return decoded if isinstance(decoded, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _short(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_token(s: str) -> bool:
    return len(s) > 20 and " " not in s


async def fetch_token(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, uid: str, pw: str
) -> dict[str, Any]:
    """একটি অ্যাকাউন্টের জন্য API কল করে ফলাফল dict ফেরত দেয় (password/token লগ হয় না)।"""
    fail = {"uid": uid, "ok": False}
    last_error = "অজানা Error"

    async with sem:
        resp: httpx.Response | None = None
        for attempt in range(2):
            try:
                resp = await client.get(API_URL, params={"uid": uid, "pass": pw})
                if resp.status_code >= 500 and attempt == 0:
                    last_error = f"API Server Error (HTTP {resp.status_code})"
                    await asyncio.sleep(1.5)
                    continue
                break
            except httpx.TimeoutException:
                last_error = "API Timeout (সময় শেষ)"
            except httpx.HTTPError as exc:
                # exc এর মেসেজে URL (password সহ) থাকতে পারে, তাই শুধু টাইপ দেখানো হচ্ছে
                last_error = f"নেটওয়ার্ক Error ({type(exc).__name__})"
            resp = None
            await asyncio.sleep(1.5)

    if resp is None:
        return {**fail, "error": last_error}

    data: Any = None
    try:
        data = resp.json()
    except ValueError:
        text = resp.text.strip()
        if JWT_RE.match(text):
            data = {"token": text}

    if resp.status_code == 429:
        return {**fail, "error": "API Rate Limit (খুব বেশি রিকোয়েস্ট)"}

    token = find_first(data, TOKEN_KEYS, _is_token) if data is not None else None

    if resp.status_code != 200 or not token:
        api_msg = find_first(data, ERROR_KEYS) if data is not None else None
        if resp.status_code != 200:
            reason = f"API Error (HTTP {resp.status_code})"
        elif data is None:
            reason = "API থেকে অবৈধ Response এসেছে"
        else:
            reason = "API Response এ Token পাওয়া যায়নি"
        if api_msg:
            reason += f": {api_msg}"
        return {**fail, "error": _short(scrub(reason, pw))}

    payload = decode_jwt_payload(token)
    region = (
        find_first(data, REGION_KEYS)
        or str(payload.get("lock_region") or payload.get("noti_region") or "")
        or DEFAULT_REGION
    ).upper()
    account_id = find_first(data, ACCOUNT_KEYS) or str(payload.get("account_id") or "")

    return {
        "uid": uid,
        "ok": True,
        "token": token,
        "region": region,
        "account_id": account_id,
    }


# ─────────────────────────────────────────────────────────────
# অনুমতি (Admin / Authorized User)
# ─────────────────────────────────────────────────────────────
def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def is_authorized(user_id: int) -> bool:
    return user_id in ADMIN_IDS or user_id in store.users


Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]


def require_auth(func: Handler) -> Handler:
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or update.effective_message is None:
            return
        if not is_authorized(user.id):
            await update.effective_message.reply_text(
                "⛔ আপনার এই বট ব্যবহারের অনুমতি নেই।\n"
                f"আপনার User ID: {user.id}\n"
                "এই ID টি Admin কে দিন, তিনি আপনাকে Access দেবেন।"
            )
            return
        await func(update, context)

    return wrapper


def require_admin(func: Handler) -> Handler:
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or update.effective_message is None:
            return
        if not is_admin(user.id):
            await update.effective_message.reply_text("⛔ এই কমান্ড শুধু Admin ব্যবহার করতে পারবেন।")
            return
        await func(update, context)

    return wrapper


# ─────────────────────────────────────────────────────────────
# কমান্ড হ্যান্ডলার
# ─────────────────────────────────────────────────────────────
HELP_TEXT = (
    "🤖 JUBYER JWT GENERATOR BOT\n\n"
    "📤 UID ও Password সহ একটি .json ফাইল পাঠান। বট স্বয়ংক্রিয়ভাবে Token তৈরি করে দেবে।\n\n"
    "সমর্থিত JSON ফরম্যাট:\n"
    '1) [{"uid": "123", "password": "abc"}, ...]\n'
    '2) {"123": "abc", "456": "def"}\n'
    '3) {"accounts": [{"uid": "123", "pass": "abc"}]}\n'
    '4) {"guest_account_info": {"com.garena.msdk.guest_uid": "123", '
    '"com.garena.msdk.guest_password": "abc"}}\n\n'
    "কমান্ড:\n"
    "/start - বট চালু\n"
    "/help - সাহায্য\n"
    "/id - আপনার Telegram ID"
)

ADMIN_HELP = (
    "\n\n👑 Admin কমান্ড:\n"
    "/add USER_ID - Access দিন\n"
    "/remove USER_ID - Access বন্ধ করুন\n"
    "/users - অনুমোদিত User তালিকা\n"
    "/export - token_bd.json ডাউনলোড"
)


@require_auth
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    text = HELP_TEXT + (ADMIN_HELP if is_admin(user.id) else "")
    await update.effective_message.reply_text(text)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user and update.effective_message:
        await update.effective_message.reply_text(f"🆔 আপনার Telegram ID: {user.id}")


def _parse_user_id(context: ContextTypes.DEFAULT_TYPE) -> int | None:
    if not context.args:
        return None
    arg = context.args[0].strip()
    return int(arg) if re.fullmatch(r"\d{1,15}", arg) else None


@require_admin
async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    target = _parse_user_id(context)
    if target is None:
        await msg.reply_text("ব্যবহার: /add USER_ID\nউদাহরণ: /add 123456789")
        return
    if await store.add_user(target):
        await msg.reply_text(f"✅ User {target} কে Access দেওয়া হয়েছে।")
        try:
            await context.bot.send_message(
                target, "✅ আপনাকে JUBYER JWT GENERATOR BOT ব্যবহারের অনুমতি দেওয়া হয়েছে। /start দিন।"
            )
        except TelegramError:
            pass  # User এখনো বট চালু করেননি – সমস্যা নেই
    else:
        await msg.reply_text(f"ℹ️ User {target} আগে থেকেই অনুমোদিত (অথবা Admin)।")


@require_admin
async def cmd_remove(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    target = _parse_user_id(context)
    if target is None:
        await msg.reply_text("ব্যবহার: /remove USER_ID\nউদাহরণ: /remove 123456789")
        return
    if target in ADMIN_IDS:
        await msg.reply_text("⚠️ Admin এর Access বন্ধ করা যাবে না।")
        return
    if await store.remove_user(target):
        await msg.reply_text(f"🚫 User {target} এর Access বন্ধ করা হয়েছে।")
    else:
        await msg.reply_text(f"ℹ️ User {target} তালিকায় নেই।")


@require_admin
async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    admins = "\n".join(f"👑 {i}" for i in sorted(ADMIN_IDS)) or "—"
    users = "\n".join(f"👤 {i}" for i in sorted(store.users)) or "কেউ নেই"
    await update.effective_message.reply_text(
        f"Admin:\n{admins}\n\nঅনুমোদিত User ({len(store.users)}):\n{users}"
    )


@require_admin
async def cmd_export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    entries = load_token_entries()
    if not entries:
        await msg.reply_text("ℹ️ এখনো কোনো token_bd.json তৈরি হয়নি।")
        return
    await msg.reply_document(
        document=io.BytesIO(json.dumps(entries, ensure_ascii=False, indent=2).encode("utf-8")),
        filename="token_bd.json",
        caption="🔐 সংরক্ষিত সব Token। গোপন রাখুন।",
        protect_content=True,
    )


@require_auth
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "📤 UID ও Password সহ একটি .json ফাইল পাঠান। বিস্তারিত: /help"
    )


# ─────────────────────────────────────────────────────────────
# JSON ফাইল আপলোড হ্যান্ডলার (মূল কাজ)
# ─────────────────────────────────────────────────────────────
@require_auth
async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    doc = msg.document
    if doc is None:
        return

    name = (doc.file_name or "").lower()
    if not (name.endswith(".json") or doc.mime_type == "application/json"):
        await msg.reply_text("❌ শুধু .json ফাইল গ্রহণযোগ্য।")
        return
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        await msg.reply_text("❌ ফাইলটি অনেক বড় (সর্বোচ্চ ৫ MB)।")
        return
    if context.user_data.get("busy"):
        await msg.reply_text("⏳ আপনার আগের ফাইল এখনো প্রক্রিয়া হচ্ছে। শেষ হওয়া পর্যন্ত অপেক্ষা করুন।")
        return

    # ফাইল ডাউনলোড ও পার্স
    try:
        tg_file = await doc.get_file()
        raw = bytes(await tg_file.download_as_bytearray())
    except TelegramError:
        await msg.reply_text("❌ ফাইল ডাউনলোড করা যায়নি। আবার চেষ্টা করুন।")
        return

    try:
        accounts = parse_accounts(raw)
    except ValueError as exc:
        await msg.reply_text(f"❌ ভুল JSON ফাইল: {exc}")
        return
    finally:
        del raw  # মেমোরি থেকে raw ডাটা সরিয়ে ফেলা

    if len(accounts) > MAX_ACCOUNTS:
        await msg.reply_text(
            f"❌ একবারে সর্বোচ্চ {MAX_ACCOUNTS} টি অ্যাকাউন্ট দেওয়া যাবে (আপনার ফাইলে {len(accounts)} টি)।"
        )
        return

    context.user_data["busy"] = True
    total = len(accounts)
    status = await msg.reply_text(f"⏳ {total} টি অ্যাকাউন্ট পাওয়া গেছে। প্রক্রিয়া শুরু হচ্ছে...")

    results: list[dict[str, Any]] = []
    try:
        sem = asyncio.Semaphore(CONCURRENCY)
        order = {uid: i for i, (uid, _) in enumerate(accounts)}
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(API_TIMEOUT),
            headers={"Accept": "application/json", "User-Agent": "JubyerJWTBot/1.0"},
            follow_redirects=True,
        ) as client:
            tasks = [asyncio.create_task(fetch_token(client, sem, uid, pw)) for uid, pw in accounts]
            last_edit = 0.0
            for fut in asyncio.as_completed(tasks):
                results.append(await fut)
                done = len(results)
                if done < total and time.monotonic() - last_edit >= 3:
                    last_edit = time.monotonic()
                    try:
                        await status.edit_text(f"⏳ প্রক্রিয়া চলছে: {done}/{total}")
                    except TelegramError:
                        pass
    except Exception as exc:  # noqa: BLE001
        log.error("Processing failed: %s", scrub(f"{type(exc).__name__}: {exc}"))
        await msg.reply_text("❌ প্রক্রিয়া চলাকালীন সমস্যা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।")
        return
    finally:
        context.user_data["busy"] = False
        accounts.clear()  # Password মেমোরি থেকে সরানো

    results.sort(key=lambda r: order.get(r["uid"], 0))
    await store.save_results(results)

    ok = [r for r in results if r["ok"]]
    bad = [r for r in results if not r["ok"]]
    regions = sorted({r["region"] for r in ok}) or [DEFAULT_REGION]

    report = (
        "📊 রিপোর্ট\n"
        "━━━━━━━━━━━━━━\n"
        f"📦 মোট অ্যাকাউন্ট: {total}\n"
        f"✅ সফল অ্যাকাউন্ট: {len(ok)}\n"
        f"❌ ব্যর্থ অ্যাকাউন্ট: {len(bad)}\n"
        f"🌍 Region: {', '.join(regions)}"
    )
    if bad:
        lines = [f"• {r['uid']} — {r['error']}" for r in bad[:10]]
        if len(bad) > 10:
            lines.append(f"… এবং আরো {len(bad) - 10} টি")
        report += "\n\n⚠️ ব্যর্থ তালিকা:\n" + "\n".join(lines)

    try:
        await status.edit_text(report)
    except TelegramError:
        await msg.reply_text(report)

    # এই রানের ফলাফল ফাইল (শুধু অনুরোধকারীকে পাঠানো হয়) – শুধু uid, token, region
    run_file = [{"uid": r["uid"], "token": r["token"], "region": r["region"]} for r in ok]
    try:
        await msg.reply_document(
            document=io.BytesIO(json.dumps(run_file, ensure_ascii=False, indent=2).encode("utf-8")),
            filename="token_bd.json",
            caption="🔐 Token গোপন রাখুন, কারো সাথে শেয়ার করবেন না।",
            protect_content=True,
        )
    except TelegramError:
        await msg.reply_text("⚠️ ফলাফল ফাইল পাঠানো যায়নি। Admin /export ব্যবহার করে সংরক্ষিত ফাইল নিতে পারবেন।")

    # আপলোড করা মেসেজে Password থাকে – চ্যাট থেকে মুছে ফেলা
    if DELETE_UPLOADED:
        try:
            await msg.delete()
        except TelegramError:
            pass


# ─────────────────────────────────────────────────────────────
# অ্যাপ সেটআপ
# ─────────────────────────────────────────────────────────────
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    log.error("Unhandled error: %s", scrub(f"{type(err).__name__}: {err}")[:300])


async def post_init(application: Application) -> None:
    await application.bot.set_my_commands(
        [
            BotCommand("start", "বট চালু করুন"),
            BotCommand("help", "সাহায্য"),
            BotCommand("id", "আপনার Telegram ID"),
            BotCommand("add", "Admin: Access দিন"),
            BotCommand("remove", "Admin: Access বন্ধ করুন"),
            BotCommand("users", "Admin: User তালিকা"),
            BotCommand("export", "Admin: token_bd.json"),
        ]
    )
    me = await application.bot.get_me()
    log.info("বট চালু হয়েছে: @%s | Admin: %d জন | Users: %d জন", me.username, len(ADMIN_IDS), len(store.users))


def main() -> None:
    if not BOT_TOKEN:
        sys.exit("❌ BOT_TOKEN সেট করা হয়নি। Environment Variables এ BOT_TOKEN দিন।")
    if not ADMIN_IDS:
        sys.exit("❌ ADMIN_ID সেট করা হয়নি। Environment Variables এ আপনার Telegram ID দিন।")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        .post_init(post_init)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("remove", cmd_remove))
    app.add_handler(CommandHandler("users", cmd_users))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)

    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
