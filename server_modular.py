import os
import time
import threading
import json
import httpx
import urllib.parse
import re
import io
import csv
import math
import ipaddress
import collections
import asyncio
import traceback
import zipfile
import copy
import uuid
import fnmatch
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI, HTTPException, Request, Form, Depends, status, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
import numpy as np

# Fuzzy
try:
    from rapidfuzz import fuzz, process as rf_process
    FUZZY_LIB = 'rapidfuzz'
    print("Using rapidfuzz (WRatio) for optimized fuzzy matching.")
except ImportError:
    from difflib import SequenceMatcher
    def ratio_fallback(a, b):
        return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100
    fuzz = type('FuzzModule', (object,), {'ratio': ratio_fallback})
    rf_process = None
    FUZZY_LIB = 'difflib'
    print("Warning: rapidfuzz not found. Falling back to slow difflib. Install with 'pip install rapidfuzz'")

# Deep Learning
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("Warning: TensorFlow not found. ML model features will be simulated.")

# Application paths and runtime configuration

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("PHISH_DATA_DIR", "").strip()
DEFAULT_THREAT_FEED_SOURCES = [
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
]
DEFAULT_TRUSTED_SOURCES = [
    # Tranco exposes the newest list through metadata, so the real CSV/ZIP URL is resolved at refresh time.
    "https://tranco-list.eu/api/lists/date/latest",
]

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except Exception:
        return default

def data_file(filename: str) -> str:
    if not DATA_DIR:
        return os.path.join(BASE_DIR, filename)
    target_dir = DATA_DIR if os.path.isabs(DATA_DIR) else os.path.join(BASE_DIR, DATA_DIR)
    try:
        os.makedirs(target_dir, exist_ok=True)
        return os.path.join(target_dir, filename)
    except OSError:
        return os.path.join(BASE_DIR, filename)

TRUSTED_GLOBAL_CACHE = data_file("trusted_global.json")



SECRET_KEY = os.environ.get("PHISH_SECRET_KEY", "your-default-very-secret-key-please-change-it")
MONGO_URI = os.environ.get("PHISH_MONGO_URI", "").strip()
MONGO_DB_NAME = os.environ.get("PHISH_DB_NAME", "phishguard")
RATE_LIMIT_CHECK_PER_MIN = int(os.environ.get("PHISH_RATE_CHECK_PER_MIN", "120"))
RATE_LIMIT_BATCH_PER_MIN = int(os.environ.get("PHISH_RATE_BATCH_PER_MIN", "40"))
RATE_LIMIT_LOGIN_PER_5MIN = int(os.environ.get("PHISH_RATE_LOGIN_PER_5MIN", "15"))
MAX_BATCH_ITEMS = int(os.environ.get("PHISH_MAX_BATCH_ITEMS", "40"))
CHECK_BATCH_CONCURRENCY = int(os.environ.get("PHISH_CHECK_BATCH_CONCURRENCY", "8"))
GSB_API_KEY = os.environ.get("PHISH_GSB_API_KEY", "").strip()
GSB_TIMEOUT_SEC = _env_float("PHISH_GSB_TIMEOUT_SEC", 2.2)
TEMP_TRUST_MIN_MINUTES = int(os.environ.get("PHISH_TEMP_TRUST_MIN_MINUTES", "5"))
TEMP_TRUST_MAX_MINUTES = int(os.environ.get("PHISH_TEMP_TRUST_MAX_MINUTES", str(30 * 24 * 60)))
TEMP_TRUST_DEFAULT_MINUTES = int(os.environ.get("PHISH_TEMP_TRUST_DEFAULT_MINUTES", "1440"))

EXTRA_TRUSTED_SOURCES = [
    u.strip()
    for u in os.environ.get("PHISH_TRUSTED_SOURCES", "").split(",")
    if u.strip()
]
TRUSTED_SOURCE_LIST = list(dict.fromkeys(DEFAULT_TRUSTED_SOURCES + EXTRA_TRUSTED_SOURCES))
EXTRA_THREAT_FEED_SOURCES = [
    u.strip()
    for u in os.environ.get("PHISH_THREAT_FEEDS", "").split(",")
    if u.strip()
]
THREAT_FEED_SOURCE_LIST = list(dict.fromkeys(DEFAULT_THREAT_FEED_SOURCES + EXTRA_THREAT_FEED_SOURCES))
# Admin and user credentials live in MongoDB so they can be managed from the panel.

RANKS = ["basic", "plus", "pro"]
DEFAULT_RANK = "basic"
TEAMS = ["general", "finance", "hr", "it"]
DEFAULT_TEAM = "general"
TEAM_SENSITIVITY_OFFSET = {
    "general": 0,
    "finance": 6,
    "hr": 3,
    "it": 2,
}
RANK_CAPS = {
    "basic": {
        "extension": {
            "sensitivity_control": False,
            "history_clear": False,
            "open_anyway": False,
            "add_trusted": False,
            "open_user_panel": True,
            "show_admin_button": False,
        },
        "panel": {
            "scan_text": True,
            "scan_file": False,
            "export_history": False,
            "redirect_chain": False,
            "domains_tab": False,
            "whitelist_manage": False,
            "blacklist_manage": False,
            "live_feed": False,
            "quick_whitelist": False,
            "quick_blacklist": False,
            "show_reasons": False,
        },
    },
    "plus": {
        "extension": {
            "sensitivity_control": True,
            "history_clear": True,
            "open_anyway": False,
            "add_trusted": True,
            "open_user_panel": True,
            "show_admin_button": False,
        },
        "panel": {
            "scan_text": True,
            "scan_file": True,
            "export_history": True,
            "redirect_chain": True,
            "domains_tab": True,
            "whitelist_manage": True,
            "blacklist_manage": False,
            "live_feed": True,
            "quick_whitelist": True,
            "quick_blacklist": False,
            "show_reasons": True,
        },
    },
    "pro": {
        "extension": {
            "sensitivity_control": True,
            "history_clear": True,
            "open_anyway": True,
            "add_trusted": True,
            "open_user_panel": True,
            "show_admin_button": False,
        },
        "panel": {
            "scan_text": True,
            "scan_file": True,
            "export_history": True,
            "redirect_chain": True,
            "domains_tab": True,
            "whitelist_manage": True,
            "blacklist_manage": True,
            "live_feed": True,
            "quick_whitelist": True,
            "quick_blacklist": True,
            "show_reasons": True,
        },
    },
    "admin": {
        "extension": {
            "sensitivity_control": True,
            "history_clear": True,
            "open_anyway": True,
            "add_trusted": True,
            "open_user_panel": True,
            "show_admin_button": True,
        },
        "panel": {
            "scan_text": True,
            "scan_file": True,
            "export_history": True,
            "redirect_chain": True,
            "domains_tab": True,
            "whitelist_manage": True,
            "blacklist_manage": True,
            "live_feed": True,
            "quick_whitelist": True,
            "quick_blacklist": True,
            "show_reasons": True,
        },
    },
}
RANK_CAPS_OVERRIDES: Dict[str, Dict[str, Dict[str, bool]]] = {}

def _deep_copy_caps(base: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(base)

def _sanitize_caps_overrides(raw: Any) -> Dict[str, Dict[str, Dict[str, bool]]]:
    sanitized: Dict[str, Dict[str, Dict[str, bool]]] = {}
    if not isinstance(raw, dict):
        return sanitized
    for rank, sections in raw.items():
        rank_key = str(rank).strip().lower()
        if rank_key not in RANK_CAPS:
            continue
        if not isinstance(sections, dict):
            continue
        sanitized[rank_key] = {}
        for section_name, caps in sections.items():
            section_key = str(section_name).strip().lower()
            if section_key not in ("panel", "extension") or not isinstance(caps, dict):
                continue
            sanitized[rank_key][section_key] = {}
            for cap_key, cap_value in caps.items():
                if cap_key not in RANK_CAPS[rank_key].get(section_key, {}):
                    continue
                sanitized[rank_key][section_key][cap_key] = bool(cap_value)
    return sanitized

def _resolve_rank_caps(rank: str, is_admin: bool = False) -> Dict[str, Any]:
    if is_admin:
        rank = "admin"
    normalized = _normalize_rank(rank)
    resolved = _deep_copy_caps(RANK_CAPS.get(normalized, RANK_CAPS[DEFAULT_RANK]))
    overrides = RANK_CAPS_OVERRIDES.get(normalized, {})
    for section_name, caps in overrides.items():
        target = resolved.setdefault(section_name, {})
        for cap_key, cap_value in caps.items():
            if cap_key in target:
                target[cap_key] = bool(cap_value)
    return resolved

def _get_rank_caps_matrix() -> Dict[str, Dict[str, Dict[str, bool]]]:
    matrix: Dict[str, Dict[str, Dict[str, bool]]] = {}
    for rank in RANK_CAPS.keys():
        matrix[rank] = _resolve_rank_caps(rank, is_admin=(rank == "admin"))
    return matrix

def _normalize_rank(rank: Optional[str]) -> str:
    if not rank:
        return DEFAULT_RANK
    rank = rank.strip().lower()
    return rank if rank in RANK_CAPS else DEFAULT_RANK

def _normalize_team(team: Optional[str]) -> str:
    if not team:
        return DEFAULT_TEAM
    team = str(team).strip().lower()
    return team if team in TEAM_SENSITIVITY_OFFSET else DEFAULT_TEAM

def _get_caps_for_session(session: dict) -> Dict[str, Any]:
    rank = "admin" if session.get("is_admin") else _normalize_rank(session.get("rank"))
    return _resolve_rank_caps(rank, is_admin=session.get("is_admin", False))

def _require_panel_cap(session: dict, cap_key: str):
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get(cap_key, False):
        raise HTTPException(status_code=403, detail="Insufficient rank for this action.")

def _set_rank_cap_override(rank: str, section: str, cap_key: str, enabled: bool):
    global RANK_CAPS_OVERRIDES
    rank_key = "admin" if str(rank).strip().lower() == "admin" else _normalize_rank(rank)
    section_key = str(section).strip().lower()
    if rank_key not in RANK_CAPS:
        raise ValueError("Invalid rank")
    if section_key not in ("panel", "extension"):
        raise ValueError("Invalid section")
    if cap_key not in RANK_CAPS[rank_key].get(section_key, {}):
        raise ValueError("Invalid capability")

    merged = copy.deepcopy(RANK_CAPS_OVERRIDES)
    rank_node = merged.setdefault(rank_key, {})
    section_node = rank_node.setdefault(section_key, {})
    base_value = bool(RANK_CAPS[rank_key][section_key][cap_key])
    if bool(enabled) == base_value:
        section_node.pop(cap_key, None)
    else:
        section_node[cap_key] = bool(enabled)

    if not section_node:
        rank_node.pop(section_key, None)
    if not rank_node:
        merged.pop(rank_key, None)

    RANK_CAPS_OVERRIDES = _sanitize_caps_overrides(merged)

def _parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "on", "enabled"}

URL_PATTERN = re.compile(r'(https?://[^\s<>"\'\)\]]+|www\.[^\s<>"\'\)\]]+)', re.IGNORECASE)
BARE_DOMAIN_PATTERN = re.compile(r'(?<!@)(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"\'\)\]]*)?', re.IGNORECASE)
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "s.id", "rebrand.ly", "bitly.com", "t.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "rb.gy",
}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "update", "secure", "account", "bank", "payment",
    "signin", "password", "wallet", "billing",
}
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "work", "rest", "gq", "cf", "ml", "tk", "fit", "cam",
}

def _normalize_url_for_parse(url: str) -> str:
    if not url:
        return url
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        return url
    return f"http://{url}"

def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _url_indicators(url: str, host: str) -> List[str]:
    indicators: List[str] = []
    normalized_url = _normalize_url_for_parse(url)
    parsed = urllib.parse.urlparse(normalized_url)
    netloc = parsed.netloc or host

    if parsed.scheme and parsed.scheme.lower() != "https":
        indicators.append("Non-HTTPS scheme")

    host_lower = (host or "").lower()
    if host_lower and any(host_lower == d or host_lower.endswith(f".{d}") for d in SHORTENER_DOMAINS):
        indicators.append("Shortener domain")

    if host_lower and _is_ip_address(host_lower):
        indicators.append("IP address in URL")

    if "@" in netloc:
        indicators.append("Userinfo (@) in URL")

    if "xn--" in host_lower:
        indicators.append("Punycode domain")

    if any(ord(ch) > 127 for ch in host_lower):
        indicators.append("Unicode in domain")

    if host_lower:
        labels = [p for p in host_lower.split(".") if p]
        if len(labels) > 3:
            indicators.append("Many subdomains")
        tld = labels[-1] if labels else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append("Suspicious TLD")

    if url and len(url) > 120:
        indicators.append("Long URL")

    path_query = f"{parsed.path}?{parsed.query}".lower()
    if any(k in path_query for k in SUSPICIOUS_KEYWORDS):
        indicators.append("Sensitive keywords in path")

    try:
        port = parsed.port
        if port and port not in (80, 443):
            indicators.append("Unusual port")
    except ValueError:
        indicators.append("Invalid port")

    return indicators

def _extract_links(text: str, limit: int = 50) -> List[str]:
    if not text:
        return []
    links = []
    seen = set()

    for match in URL_PATTERN.findall(text):
        url = match.rstrip('.,);]')
        if url.lower().startswith('www.'):
            url = f"http://{url}"
        if url not in seen:
            seen.add(url)
            links.append(url)
        if len(links) >= limit:
            return links

    for match in BARE_DOMAIN_PATTERN.findall(text):
        domain = match.rstrip('.,);]')
        # avoid duplicates already captured via full URL
        if domain in seen:
            continue
        url = f"http://{domain}"
        if url not in seen:
            seen.add(url)
            links.append(url)
        if len(links) >= limit:
            break

    return links

def _short_reason(reasons: List[str]) -> str:
    if not reasons:
        return "No reason"
    text = " | ".join(reasons)
    if "blacklist" in text.lower():
        return "Blacklisted"
    if "known malicious domain" in text.lower() or "threat feed" in text.lower():
        return "Threat feed hit"
    if "trusted by user" in text.lower():
        return "Trusted (user)"
    if "trusted globally" in text.lower():
        return "Trusted (global)"
    if "temporarily trusted" in text.lower():
        return "Temporary trusted"
    if "shortener domain" in text.lower():
        return "Shortened URL"
    if "ip address in url" in text.lower():
        return "IP in URL"
    if "userinfo" in text.lower():
        return "Userinfo in URL"
    if "punycode domain" in text.lower():
        return "Punycode domain"
    if "unicode in domain" in text.lower():
        return "Unicode domain"
    if "many subdomains" in text.lower():
        return "Many subdomains"
    if "suspicious tld" in text.lower():
        return "Suspicious TLD"
    if "long url" in text.lower():
        return "Long URL"
    if "non-https scheme" in text.lower():
        return "Non-HTTPS URL"
    if "sensitive keywords" in text.lower():
        return "Sensitive keywords"
    if "unusual port" in text.lower():
        return "Unusual port"
    if "no trusted domain similar enough" in text.lower():
        return "No similar trusted domain"
    if "fuzzy match" in text.lower():
        return "Looks similar to trusted domain"
    if "ml risk score" in text.lower():
        return "ML risk signal"
    if "google safe browsing match" in text.lower():
        return "Safe Browsing match"
    if "brand token matched" in text.lower() or "brand injection" in text.lower():
        return "Brand impersonation pattern"
    return reasons[0]

def _levenshtein_distance(a: str, b: str) -> int:
    a = a or ""
    b = b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            repl = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, repl))
        prev = curr
    return prev[-1]

async def _redirect_chain(url: str, max_hops: int = 8) -> List[str]:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
            chain = [str(r.url) for r in resp.history] + [str(resp.url)]
            return chain[:max_hops]
    except Exception:
        return []

def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def _parse_time(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._lock = threading.Lock()
        self._hits: Dict[str, collections.deque] = {}

    def allow(self, key: str, cost: int = 1) -> Tuple[bool, int]:
        now = time.time()
        cost = max(1, int(cost))
        window_start = now - self.window_seconds

        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = collections.deque()
                self._hits[key] = dq

            while dq and dq[0] < window_start:
                dq.popleft()

            if len(dq) + cost > self.limit:
                retry_after = max(1, int(self.window_seconds - (now - dq[0]))) if dq else self.window_seconds
                return False, retry_after

            for _ in range(cost):
                dq.append(now)
            return True, 0



PASSWORD_HASH_PREFIX = "pbkdf2_sha256$"

def _hash_password(password: str) -> str:
    """Hash a password with a per-user salt using only the Python standard library."""
    salt = secrets.token_hex(16)
    rounds = 210_000
    digest = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt.encode("utf-8"), rounds)
    return f"{PASSWORD_HASH_PREFIX}{rounds}${salt}${digest.hex()}"

def _verify_password(stored_password: str, provided_password: str) -> bool:
    """Accept current PBKDF2 hashes and legacy plaintext values during migration."""
    stored_password = str(stored_password or "")
    provided_password = str(provided_password or "")
    if not stored_password.startswith(PASSWORD_HASH_PREFIX):
        return secrets.compare_digest(stored_password, provided_password)
    try:
        _, rounds_raw, salt, digest_hex = stored_password.split("$", 3)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            provided_password.encode("utf-8"),
            salt.encode("utf-8"),
            int(rounds_raw),
        ).hex()
        return secrets.compare_digest(digest, digest_hex)
    except Exception:
        return False

def _password_needs_upgrade(stored_password: str) -> bool:
    return not str(stored_password or "").startswith(PASSWORD_HASH_PREFIX)

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"

class MongoStore:
    def __init__(self, uri: str, db_name: str):
        self.client = AsyncIOMotorClient(uri)
        self.db = self.client[db_name]
        self.admin_users = self.db["admin_users"]
        self.normal_users = self.db["normal_users"]
        self.settings = self.db["settings"]
        self.audit_logs = self.db["audit_logs"]
        self.feedback = self.db["feedback"]

    async def ensure_defaults(self):
        if await self.admin_users.count_documents({}) == 0:
            await self.admin_users.insert_one({
                "_id": "admin",
                "password": _hash_password("12345"),
                "display_name": "Default Admin",
            })
        if await self.normal_users.count_documents({}) == 0:
            await self.normal_users.insert_one({
                "_id": "user",
                "password": _hash_password("123"),
                "display_name": "Normal User",
                "rank": DEFAULT_RANK,
                "team": DEFAULT_TEAM,
            })

        await self.settings.update_one(
            {"_id": "server_sensitivity"},
            {"$setOnInsert": {"value": 90}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "user_trusted"},
            {"$setOnInsert": {"value": []}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "user_blacklist"},
            {"$setOnInsert": {"value": []}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "temporary_trusted"},
            {"$setOnInsert": {"value": []}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "rank_caps_overrides"},
            {"$setOnInsert": {"value": {}}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "feedback_domain_bias"},
            {"$setOnInsert": {"value": {}}},
            upsert=True,
        )
        await self.settings.update_one(
            {"_id": "honey_tokens"},
            {"$setOnInsert": {"value": []}},
            upsert=True,
        )
        await self.audit_logs.create_index([("time", -1)])
        await self.feedback.create_index([("time", -1)])
        await self.feedback.create_index([("domain", 1)])
        await self.feedback.create_index([("feedback_id", 1)], unique=True, sparse=True)

        await self.normalize_normal_user_ranks()

    async def normalize_normal_user_ranks(self):
        cursor = self.normal_users.find({})
        async for doc in cursor:
            current = doc.get("rank")
            normalized = _normalize_rank(current)
            team_current = doc.get("team")
            normalized_team = _normalize_team(team_current)
            updates = {}
            if current != normalized:
                updates["rank"] = normalized
            if team_current != normalized_team:
                updates["team"] = normalized_team
            if updates:
                await self.normal_users.update_one(
                    {"_id": doc["_id"]},
                    {"$set": updates},
                )

    async def get_admin_user(self, username: str) -> Optional[Dict[str, Any]]:
        return await self.admin_users.find_one({"_id": username})

    async def get_normal_user(self, username: str) -> Optional[Dict[str, Any]]:
        return await self.normal_users.find_one({"_id": username})

    async def get_all_admin_users(self) -> Dict[str, Dict[str, Any]]:
        users = {}
        async for doc in self.admin_users.find({}):
            users[doc["_id"]] = {
                "display_name": doc.get("display_name", doc["_id"]),
            }
        return users

    async def get_all_normal_users(self) -> Dict[str, Dict[str, Any]]:
        users = {}
        async for doc in self.normal_users.find({}):
            users[doc["_id"]] = {
                "display_name": doc.get("display_name", doc["_id"]),
                "rank": _normalize_rank(doc.get("rank")),
                "team": _normalize_team(doc.get("team")),
            }
        return users

    async def add_admin_user(self, username: str, password: str, display_name: str) -> bool:
        existing = await self.get_admin_user(username)
        if existing:
            return False
        await self.admin_users.insert_one({
            "_id": username,
            "password": _hash_password(password),
            "display_name": display_name,
        })
        return True


    async def update_admin_password(self, username: str, password: str) -> bool:
        result = await self.admin_users.update_one(
            {"_id": username},
            {"$set": {"password": _hash_password(password)}},
        )
        return result.matched_count > 0

    async def remove_admin_user(self, username: str) -> bool:
        result = await self.admin_users.delete_one({"_id": username})
        return result.deleted_count > 0

    async def admin_count(self) -> int:
        return await self.admin_users.count_documents({})

    async def add_normal_user(self, username: str, password: str, display_name: str, rank: str, team: str = DEFAULT_TEAM) -> bool:
        existing = await self.get_normal_user(username)
        if existing:
            return False
        await self.normal_users.insert_one({
            "_id": username,
            "password": _hash_password(password),
            "display_name": display_name,
            "rank": _normalize_rank(rank),
            "team": _normalize_team(team),
        })
        return True


    async def update_normal_user_password(self, username: str, password: str) -> bool:
        result = await self.normal_users.update_one(
            {"_id": username},
            {"$set": {"password": _hash_password(password)}},
        )
        return result.matched_count > 0

    async def remove_normal_user(self, username: str) -> bool:
        result = await self.normal_users.delete_one({"_id": username})
        return result.deleted_count > 0

    async def update_normal_user_rank(self, username: str, rank: str) -> bool:
        result = await self.normal_users.update_one(
            {"_id": username},
            {"$set": {"rank": _normalize_rank(rank)}},
        )
        return result.matched_count > 0

    async def update_normal_user_team(self, username: str, team: str) -> bool:
        result = await self.normal_users.update_one(
            {"_id": username},
            {"$set": {"team": _normalize_team(team)}},
        )
        return result.matched_count > 0

    async def get_setting(self, key: str, default: Any = None) -> Any:
        doc = await self.settings.find_one({"_id": key})
        if not doc:
            return default
        return doc.get("value", default)

    async def set_setting(self, key: str, value: Any):
        await self.settings.update_one(
            {"_id": key},
            {"$set": {"value": value}},
            upsert=True,
        )

    async def get_list(self, key: str) -> List[str]:
        value = await self.get_setting(key, [])
        if isinstance(value, list):
            return value
        return []

    async def set_list(self, key: str, values: List[str]):
        await self.set_setting(key, values)

    async def get_temp_trusted_rows(self) -> List[Dict[str, Any]]:
        value = await self.get_setting("temporary_trusted", [])
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        return []

    async def set_temp_trusted_rows(self, rows: List[Dict[str, Any]]):
        await self.set_setting("temporary_trusted", rows)

    async def get_rank_caps_overrides(self) -> Dict[str, Any]:
        value = await self.get_setting("rank_caps_overrides", {})
        return value if isinstance(value, dict) else {}

    async def set_rank_caps_overrides(self, value: Dict[str, Any]):
        await self.set_setting("rank_caps_overrides", value)

    async def get_feedback_domain_bias(self) -> Dict[str, Any]:
        value = await self.get_setting("feedback_domain_bias", {})
        return value if isinstance(value, dict) else {}

    async def set_feedback_domain_bias(self, value: Dict[str, Any]):
        await self.set_setting("feedback_domain_bias", value)

    async def get_honey_tokens(self) -> List[Dict[str, Any]]:
        value = await self.get_setting("honey_tokens", [])
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    async def set_honey_tokens(self, rows: List[Dict[str, Any]]):
        await self.set_setting("honey_tokens", rows)

    async def get_extension_filename(self) -> Optional[str]:
        return await self.get_setting("extension_filename", None)

    async def set_extension_filename(self, filename: Optional[str]):
        await self.set_setting("extension_filename", filename)

    async def get_server_sensitivity(self, default: int) -> int:
        value = await self.get_setting("server_sensitivity", default)
        try:
            return int(value)
        except Exception:
            return default

    async def set_server_sensitivity(self, value: int):
        await self.set_setting("server_sensitivity", int(value))

    async def add_audit_log(
        self,
        actor: str,
        action: str,
        target: str = "",
        meta: Optional[Dict[str, Any]] = None,
        ip: str = "",
    ):
        await self.audit_logs.insert_one({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": actor or "unknown",
            "action": action,
            "target": target,
            "ip": ip,
            "meta": meta or {},
        })

    async def get_recent_audit_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cursor = self.audit_logs.find({}).sort("time", -1).limit(max(1, min(limit, 2000)))
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(doc)
        return items

    async def add_feedback(self, payload: Dict[str, Any]):
        doc = dict(payload)
        doc["time"] = _now_str()
        doc["feedback_id"] = doc.get("feedback_id") or str(uuid.uuid4())
        doc["status"] = doc.get("status") or "open"
        await self.feedback.insert_one(doc)
        return doc["feedback_id"]

    async def get_feedback_recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cursor = self.feedback.find({}).sort("time", -1).limit(max(1, min(limit, 2000)))
        async for doc in cursor:
            if not doc.get("feedback_id"):
                doc["feedback_id"] = str(doc.get("_id", ""))
            doc.pop("_id", None)
            items.append(doc)
        return items

    async def update_feedback_status(self, feedback_id: str, status_value: str, resolver: str, action: str = "") -> bool:
        if not feedback_id:
            return False
        update_doc = {
            "status": status_value,
            "resolved_by": resolver,
            "resolved_action": action,
            "resolved_at": _now_str(),
        }
        result = await self.feedback.update_one({"feedback_id": feedback_id}, {"$set": update_doc})
        if result.matched_count > 0:
            return True
        # backward compatibility for old docs without feedback_id
        result = await self.feedback.update_one({"_id": feedback_id}, {"$set": update_doc})
        return result.matched_count > 0

    async def get_feedback_item(self, feedback_id: str) -> Optional[Dict[str, Any]]:
        if not feedback_id:
            return None
        doc = await self.feedback.find_one({"feedback_id": feedback_id})
        if not doc:
            return None
        doc["feedback_id"] = doc.get("feedback_id") or str(doc.get("_id", ""))
        doc.pop("_id", None)
        return doc


mongo_store: Optional[MongoStore] = None

app = FastAPI(title="Local Phishing Detector API")

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# User data is stored in MongoDB through MongoStore.


# Lightweight ML-style risk scorer. It uses TensorFlow when available and falls back safely otherwise.
class MLPhishingModel:
    INPUT_DIM = 6
    def __init__(self):
        self.tf_model = None
        self.is_healthy = False
        if TF_AVAILABLE:
            try:
                self._build_keras_model()
                self.is_healthy = True
            except Exception as e:
                self.is_healthy = False
                print(f"MLPhishingModel FAILED to load: {e}")
        else:
            self.is_healthy = True  # Keep the service usable even when TensorFlow is not installed.
    def _build_keras_model(self):
        self.tf_model = Sequential([Dense(12, activation='relu', input_shape=(self.INPUT_DIM,)), Dense(6, activation='relu'), Dense(1, activation='sigmoid')])
        self.tf_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.tf_model.set_weights([np.random.rand(self.INPUT_DIM, 12) * 0.1, np.random.rand(12) * 0.1, np.random.rand(12, 6) * 0.1, np.random.rand(6) * 0.1, np.random.rand(6, 1) * 0.1, np.random.rand(1) * 0.1])
    def _calculate_entropy(self, s: str) -> float:
        if not s: return 0.0
        p = collections.Counter(s); total_len = len(s); entropy = 0.0
        for count in p.values(): probability = count / total_len; entropy -= probability * math.log2(probability)
        return entropy
    def predict_risk(self, target_host: str, similar_to: Optional[str], similarity_score: int) -> float:
        target_len = len(target_host)
        similarity_feature = max(0.0, (similarity_score - 70) / 30.0)
        entropy_score = self._calculate_entropy(target_host); entropy_feature = min(1.0, entropy_score / 4.0)
        digit_count = sum(c.isdigit() for c in target_host); digit_feature = 1.0 if digit_count > 0 and target_len > 5 else 0.0
        keywords = ["login", "secure", "verify", "account", "update", "bank", "payment", "service"]; keyword_feature = 1.0 if any(kw in target_host for kw in keywords) else 0.0
        suspicious_sub_domains = ["login", "secure", "verify", "webid", "support"]; sub_domain_feature = 0.0
        if similar_to:
            if target_host.endswith(similar_to.replace('.', '-')): sub_domain_feature = 1.0
            if any(target_host.startswith(f"{sub}.") for sub in suspicious_sub_domains): sub_domain_feature = max(sub_domain_feature, 0.7)
        unicode_feature = 1.0 if any(ord(c) > 127 for c in target_host.lower()) and not target_host.isascii() else 0.0
        feature_vector = np.array([similarity_feature, entropy_feature, digit_feature, keyword_feature, sub_domain_feature, unicode_feature])
        risk_score = 0.0
        if not self.is_healthy or not TF_AVAILABLE:
            W_SIMILARITY = 0.50; W_ENTROPY = 0.15; W_DIGIT = 0.10; W_KEYWORD = 0.10; W_SUBDOMAIN = 0.10; W_UNICODE = 0.05
            risk_score = (similarity_feature * W_SIMILARITY) + (entropy_feature * W_ENTROPY) + (digit_feature * W_DIGIT) + (keyword_feature * W_KEYWORD) + (sub_domain_feature * W_SUBDOMAIN) + (unicode_feature * W_UNICODE)
            total_weights = W_SIMILARITY + W_ENTROPY + W_DIGIT + W_KEYWORD + W_SUBDOMAIN + W_UNICODE
            risk_score = min(1.0, risk_score / total_weights if total_weights > 0 else 0)
        elif self.tf_model and TF_AVAILABLE:
            try: input_data = feature_vector.reshape(1, self.INPUT_DIM); risk_score = self.tf_model.predict(input_data, verbose=0)[0][0]
            except Exception as e: self.is_healthy = False; print(f"ML Prediction Failed: {e}"); risk_score = 0.5
        return float(risk_score)

# Main phishing detector and in-memory runtime state.
class PhishDetector:

    TRUSTED_CACHE = TRUSTED_GLOBAL_CACHE
    REPO_RAW_URL = "https://s27.uupload.ir/files/09171258914/cloudflare-radar_top-1000000-domains_20251103-20251110.csv"
    TRUSTED_SOURCES = list(dict.fromkeys([REPO_RAW_URL] + TRUSTED_SOURCE_LIST))
    THREAT_FEED_SOURCES = THREAT_FEED_SOURCE_LIST
    EXTENSION_UPLOAD_DIR = os.path.join(BASE_DIR, "static", "extension_files")
    MAX_FUZZY_CANDIDATES = 1200
    RESULT_CACHE_MAX_ITEMS = 12000
    RESULT_CACHE_TTL_SAFE = 10 * 60
    RESULT_CACHE_TTL_PHISH = 45 * 60
    RESULT_CACHE_TTL_ERROR = 60

    def __init__(self):
        # Locks keep background refreshes and API requests from stepping on each other.
        self.list_lock = threading.RLock()
        self.reports_lock = threading.Lock()
        self.timeline_lock = threading.Lock()
        self.sensitivity_lock = threading.RLock()
        self.health_lock = threading.Lock()
        self.result_cache_lock = threading.Lock()
        self.gsb_cache_lock = threading.Lock()

        # Runtime data stores.
        self.trusted_global: Set[str] = set()
        self.threat_feed: Set[str] = set()
        self.user_trusted: Set[str] = set()
        self.temp_user_trusted: Dict[str, Dict[str, Any]] = {}
        # Manual blacklist store.
        self.user_blacklist: Set[str] = set()
        self.reports: List[Dict[str, Any]] = []
        self.domain_timeline: Dict[str, List[Dict[str, Any]]] = {}
        self.domain_fingerprints: Dict[str, Dict[str, Any]] = {}
        self.honey_events: List[Dict[str, Any]] = []
        self.honey_tokens: Dict[str, Dict[str, Any]] = {}
        self.feedback_domain_bias: Dict[str, Dict[str, int]] = {}
        self.scan_history_lock = threading.Lock()
        self.scan_history: List[Dict[str, Any]] = []
        self.server_sensitivity = 90  # Mongo overrides this after startup.

        self.extension_filename: Optional[str] = None
        self.global_tld_index: Dict[str, Dict[str, List[str]]] = {}
        self.result_cache: Dict[str, Dict[str, Any]] = {}
        self.gsb_cache: Dict[str, Dict[str, Any]] = {}
        self.store: Optional[MongoStore] = None
        os.makedirs(self.EXTENSION_UPLOAD_DIR, exist_ok=True)

        self.ml_model = MLPhishingModel()

        self.health_status = {
            "ml_model": "OK" if self.ml_model.is_healthy else "FAILED",
            "global_cache": "CHECKING",
            "threat_feed_status": "CHECKING",
            "trusted_last_refresh": None,
            "threat_last_refresh": None,
            "source_status": {},
            "last_ping": time.time(),
        }
        self.gsb_api_key = GSB_API_KEY
        self.gsb_timeout_sec = max(0.8, min(5.0, GSB_TIMEOUT_SEC))

        self._load_data_on_startup()
        print(f"PhishDetector initialized. Sensitivity: {self.server_sensitivity}%")

    # Utility helpers for normalization, matching and caching.
    def _normalize_host(self, u: str) -> str:
        s = (u or "").strip().lower()
        if "://" in s: s = urllib.parse.urlparse(s).netloc
        s = s.split("/", 1)[0].split(":")[0]
        return s.replace("www.", "")

    def _host_or_parent_in_set(self, host: str, domains: Set[str]) -> Tuple[bool, Optional[str]]:
        labels = [p for p in (host or "").split(".") if p]
        if len(labels) < 2:
            return False, None
        for i in range(0, len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in domains:
                return True, candidate
        return False, None

    def _host_matches_patterns(self, host: str, patterns: Set[str]) -> Tuple[bool, Optional[str]]:
        host_l = (host or "").lower().strip()
        if not host_l:
            return False, None
        for raw_pattern in patterns:
            p = (raw_pattern or "").lower().strip()
            if not p or "*" not in p and not p.startswith("."):
                continue
            if p.startswith("*."):
                suffix = p[2:]
                if host_l == suffix or host_l.endswith(f".{suffix}"):
                    return True, raw_pattern
                continue
            if p.startswith("."):
                suffix = p[1:]
                if host_l == suffix or host_l.endswith(f".{suffix}"):
                    return True, raw_pattern
                continue
            if fnmatch.fnmatch(host_l, p):
                return True, raw_pattern
        return False, None

    def _similarity(self, a: str, b: str) -> int:
        if not a or not b: return 0
        if FUZZY_LIB == 'rapidfuzz': return int(fuzz.WRatio(a.lower(), b.lower()))
        else: return int(fuzz.ratio(a.lower(), b.lower()))

    def _extract_tld(self, host: str) -> str:
        parts = (host or "").split(".")
        if len(parts) < 2:
            return ""
        return parts[-1]

    def _extract_sld(self, host: str) -> str:
        parts = (host or "").split(".")
        if len(parts) < 2:
            return host or ""
        return parts[-2]

    def _rebuild_global_index(self):
        idx: Dict[str, Dict[str, List[str]]] = {}
        with self.list_lock:
            for domain in self.trusted_global:
                tld = self._extract_tld(domain)
                sld = self._extract_sld(domain)
                if not tld or not sld:
                    continue
                first = sld[0]
                idx.setdefault(tld, {}).setdefault(first, []).append(domain)
        self.global_tld_index = idx

    def _clear_result_cache(self):
        with self.result_cache_lock:
            self.result_cache = {}

    def _cache_key(self, host: str, sensitivity: int) -> str:
        return f"{int(sensitivity)}|{host}"

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self.result_cache_lock:
            entry = self.result_cache.get(key)
            if not entry:
                return None
            if entry.get("expires_at", 0) <= now:
                self.result_cache.pop(key, None)
                return None
            return dict(entry.get("result", {}))

    def _cache_set(self, key: str, result: Dict[str, Any]):
        if not key:
            return
        if result.get("error"):
            ttl = self.RESULT_CACHE_TTL_ERROR
        elif result.get("is_phishing"):
            ttl = self.RESULT_CACHE_TTL_PHISH
        else:
            ttl = self.RESULT_CACHE_TTL_SAFE

        now = time.time()
        with self.result_cache_lock:
            self.result_cache[key] = {
                "result": dict(result),
                "expires_at": now + ttl,
                "touched_at": now,
            }
            if len(self.result_cache) <= self.RESULT_CACHE_MAX_ITEMS:
                return
            oldest_key = None
            oldest_touched = float("inf")
            for k, v in self.result_cache.items():
                touched = v.get("touched_at", now)
                if touched < oldest_touched:
                    oldest_touched = touched
                    oldest_key = k
            if oldest_key:
                self.result_cache.pop(oldest_key, None)

    def _gsb_cache_get(self, url: str) -> Optional[Tuple[bool, str]]:
        now = time.time()
        with self.gsb_cache_lock:
            entry = self.gsb_cache.get(url)
            if not entry:
                return None
            if entry.get("expires_at", 0) <= now:
                self.gsb_cache.pop(url, None)
                return None
            return bool(entry.get("matched", False)), str(entry.get("threat", ""))

    def _gsb_cache_set(self, url: str, matched: bool, threat: str):
        ttl = 12 * 60 if matched else 30 * 60
        with self.gsb_cache_lock:
            self.gsb_cache[url] = {
                "matched": bool(matched),
                "threat": threat or "",
                "expires_at": time.time() + ttl,
            }
            if len(self.gsb_cache) > 6000:
                # Trim oldest random-ish item by expiration time.
                oldest_key = min(self.gsb_cache, key=lambda k: self.gsb_cache[k].get("expires_at", 0))
                self.gsb_cache.pop(oldest_key, None)

    def _candidate_domains(self, target_host: str) -> List[str]:
        target_tld = self._extract_tld(target_host)
        target_sld = self._extract_sld(target_host)
        first = target_sld[0] if target_sld else ""
        target_len = len(target_host)

        with self.list_lock:
            tld_buckets = self.global_tld_index.get(target_tld, {})
            same_first = list(tld_buckets.get(first, []))
            user_local = [d for d in self.user_trusted if "*" not in d and not d.startswith(".")]

        seed: List[str] = same_first

        # If the "same first char + same TLD" bucket is tiny, add a very small sample
        # from other buckets to avoid missing obvious lookalikes.
        if len(seed) < 200 and tld_buckets:
            for bucket_key, values in tld_buckets.items():
                if bucket_key == first:
                    continue
                seed.extend(values[:50])
                if len(seed) >= self.MAX_FUZZY_CANDIDATES * 2:
                    break

        # Rare fallback for uncommon TLDs where index has no data.
        if not seed:
            with self.list_lock:
                for d in self.trusted_global:
                    if abs(len(d) - target_len) > 8:
                        continue
                    seed.append(d)
                    if len(seed) >= 500:
                        break

        candidates: List[str] = []
        seen: Set[str] = set()

        for d in seed:
            if abs(len(d) - target_len) > 8:
                continue
            if d in seen:
                continue
            seen.add(d)
            candidates.append(d)
            if len(candidates) >= self.MAX_FUZZY_CANDIDATES:
                break

        # Always include user trusted domains (usually small), even if length differs.
        for d in user_local:
            if d in seen:
                continue
            seen.add(d)
            candidates.append(d)
            if len(candidates) >= self.MAX_FUZZY_CANDIDATES + 200:
                break

        return candidates

    def _to_lite_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "is_phishing": bool(result.get("is_phishing", False)),
            "domain": result.get("domain", ""),
            "probability": int(result.get("probability", 0) or 0),
            "threshold": result.get("threshold"),
            "similar_to": result.get("similar_to"),
            "error": result.get("error"),
        }

    def _cleanup_expired_temp_trusted(self) -> bool:
        now = time.time()
        removed_any = False
        with self.list_lock:
            expired = [host for host, row in self.temp_user_trusted.items() if float(row.get("expires_at", 0)) <= now]
            for host in expired:
                self.temp_user_trusted.pop(host, None)
                removed_any = True
        return removed_any

    def get_temp_trusted_items(self, limit: int = 200) -> List[Dict[str, Any]]:
        self._cleanup_expired_temp_trusted()
        with self.list_lock:
            rows = []
            for host, row in self.temp_user_trusted.items():
                rows.append({
                    "host": host,
                    "expires_at": int(row.get("expires_at", 0)),
                    "added_by": row.get("added_by", ""),
                    "note": row.get("note", ""),
                })
        rows.sort(key=lambda x: x["expires_at"])
        return rows[:max(1, min(limit, 2000))]

    async def _persist_temp_trusted(self):
        if not self.store:
            return
        rows = self.get_temp_trusted_items(limit=4000)
        await self.store.set_temp_trusted_rows(rows)

    async def add_temp_user_trusted(self, host: str, minutes: int, added_by: str, note: str = "") -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        ttl = max(TEMP_TRUST_MIN_MINUTES, min(TEMP_TRUST_MAX_MINUTES, int(minutes or TEMP_TRUST_DEFAULT_MINUTES)))
        expires_at = int(time.time() + (ttl * 60))
        with self.list_lock:
            self.temp_user_trusted[host] = {
                "host": host,
                "expires_at": expires_at,
                "added_by": (added_by or "")[:64],
                "note": (note or "")[:160],
            }
        await self._persist_temp_trusted()
        self._clear_result_cache()
        return True

    async def remove_temp_user_trusted(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        removed = False
        with self.list_lock:
            if host in self.temp_user_trusted:
                self.temp_user_trusted.pop(host, None)
                removed = True
        if removed:
            await self._persist_temp_trusted()
            self._clear_result_cache()
        return removed

    def _heuristic_risk(self, target_url: str, host: str, indicators: List[str]) -> int:
        weights = {
            "Shortener domain": 18,
            "IP address in URL": 35,
            "Userinfo (@) in URL": 22,
            "Punycode domain": 24,
            "Unicode in domain": 16,
            "Many subdomains": 12,
            "Long URL": 10,
            "Sensitive keywords in path": 14,
            "Unusual port": 12,
            "Invalid port": 12,
            "Non-HTTPS scheme": 8,
            "Suspicious TLD": 16,
        }
        score = 0
        for indicator in indicators:
            score += weights.get(indicator, 0)

        host_l = (host or "").lower()
        sld = self._extract_sld(host_l)
        if sld.count('-') >= 2:
            score += 8
        if len(sld) >= 20:
            score += 8
        digit_count = sum(c.isdigit() for c in sld)
        if digit_count >= 3:
            score += 10

        # If URL path contains multiple sensitive words, boost slightly.
        path_l = _normalize_url_for_parse(target_url).lower()
        keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in path_l)
        if keyword_hits >= 2:
            score += 10

        return max(0, min(85, int(score)))

    def _brand_injection_signal(self, target_host: str, candidates: List[str]) -> Tuple[int, Optional[str]]:
        """
        Detect hosts like `google-security-login.com` where a trusted brand token
        exists inside a longer suspicious SLD.
        """
        target_sld = self._extract_sld((target_host or "").lower())
        if len(target_sld) < 8:
            return 0, None

        best_brand_domain: Optional[str] = None
        best_score = 0

        # Keep this bounded so every check stays cheap.
        for domain in candidates[:500]:
            brand = self._extract_sld((domain or "").lower())
            if len(brand) < 4 or brand == target_sld:
                continue
            if brand not in target_sld:
                continue

            remainder = target_sld.replace(brand, " ")
            remainder_tokens = [t for t in re.split(r"[^a-z0-9]+", remainder) if t]
            if not remainder_tokens:
                continue

            score = 8
            if any(t in SUSPICIOUS_KEYWORDS for t in remainder_tokens):
                score += 12
            if sum(c.isdigit() for c in "".join(remainder_tokens)) >= 2:
                score += 4
            if len(remainder_tokens) >= 2:
                score += 3

            if score > best_score:
                best_score = score
                best_brand_domain = domain

        return min(30, best_score), best_brand_domain

    # Small JSON helpers kept for local fallback/cache files.
    def _save_json_set(self, path: str, data: Set[str]):
        with self.list_lock:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(sorted(list(data)), f, ensure_ascii=False, indent=2)
            except Exception as e: print(f"[_save_json_set] error saving {path}: {e}")

    def _load_json_set(self, path: str) -> Set[str]:
        # This is normally called during startup; refresh paths already take their own locks.
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    # Normalize each row as it comes back from disk.
                    return set(self._normalize_host(d) for d in json.load(f) if self._normalize_host(d))
        except Exception as e: print(f"[_load_json_set] error loading {path}: {e}"); return set()
        return set()

    def _cleanup_old_extension_files(self, current_filename: str):
        try:
            for filename in os.listdir(self.EXTENSION_UPLOAD_DIR):
                if filename != current_filename:
                    file_path = os.path.join(self.EXTENSION_UPLOAD_DIR, filename)
                    if os.path.isfile(file_path): os.remove(file_path); print(f"Cleaned up: {filename}")
        except Exception as e: print(f"Error during file cleanup: {e}")

    async def set_extension_filename(self, filename: Optional[str]):
        self.extension_filename = filename
        if self.store:
            await self.store.set_extension_filename(filename)

    def get_extension_path(self) -> Optional[str]:
        if self.extension_filename: return f"/static/extension_files/{self.extension_filename}"
        return None

    # Data loading and refresh lifecycle.
    def _load_data_on_startup(self):
        self.user_trusted = set()
        self.user_blacklist = set()
        self.temp_user_trusted = {}
        self.feedback_domain_bias = {}
        self.domain_timeline = {}
        self.domain_fingerprints = {}
        self.honey_events = []
        self.honey_tokens = {}
        self.trusted_global = self._load_json_set(self.TRUSTED_CACHE)
        self._rebuild_global_index()
        self._clear_result_cache()
        print(f"Loaded {len(self.trusted_global)} global domains. User lists will load from MongoDB.")

    async def load_from_store(self, store: MongoStore):
        self.store = store
        trusted = await store.get_list("user_trusted")
        blacklist = await store.get_list("user_blacklist")
        temp_trusted_rows = await store.get_temp_trusted_rows()
        feedback_bias_raw = await store.get_feedback_domain_bias()
        honey_rows = await store.get_honey_tokens()
        self.user_trusted = set(self._normalize_host(d) for d in trusted if self._normalize_host(d))
        self.user_blacklist = set(self._normalize_host(d) for d in blacklist if self._normalize_host(d))
        temp_map: Dict[str, Dict[str, Any]] = {}
        now = time.time()
        for row in temp_trusted_rows:
            host = self._normalize_host(str(row.get("host", "")))
            if not host:
                continue
            expires_at = int(row.get("expires_at", 0) or 0)
            if expires_at <= now:
                continue
            temp_map[host] = {
                "host": host,
                "expires_at": expires_at,
                "added_by": str(row.get("added_by", ""))[:64],
                "note": str(row.get("note", ""))[:160],
            }
        self.temp_user_trusted = temp_map
        self.extension_filename = await store.get_extension_filename()
        self.server_sensitivity = await store.get_server_sensitivity(self.server_sensitivity)
        bias_map: Dict[str, Dict[str, int]] = {}
        if isinstance(feedback_bias_raw, dict):
            for host, row in feedback_bias_raw.items():
                norm = self._normalize_host(str(host))
                if not norm or not isinstance(row, dict):
                    continue
                bias_map[norm] = {
                    "fp": int(row.get("fp", 0) or 0),
                    "fn": int(row.get("fn", 0) or 0),
                }
        self.feedback_domain_bias = bias_map

        tokens: Dict[str, Dict[str, Any]] = {}
        for row in honey_rows:
            token = str(row.get("token", "")).strip()
            if not token:
                continue
            tokens[token] = {
                "token": token,
                "label": str(row.get("label", "training")).strip()[:80],
                "created_by": str(row.get("created_by", ""))[:64],
                "created_at": str(row.get("created_at", _now_str())),
                "hits": int(row.get("hits", 0) or 0),
                "last_hit": str(row.get("last_hit", "")),
            }
        self.honey_tokens = tokens
        self._clear_result_cache()
        print(
            f"Mongo load: {len(self.user_trusted)} trusted, {len(self.user_blacklist)} blacklisted, "
            f"{len(self.temp_user_trusted)} temp-trusted domains. Sensitivity: {self.server_sensitivity}%"
        )

    async def _refresh_trusted_global(self):
        sources = list(dict.fromkeys(self.TRUSTED_SOURCES))
        print(f"Refreshing global trusted list from {len(sources)} source(s) (Async)...")
        source_status: Dict[str, str] = {}

        def _process_lines(lines: List[str]) -> Set[str]:
            temp_set: Set[str] = set()
            for line in lines:
                parts = line.split(',', 1)
                domain_part = parts[1] if len(parts) == 2 else parts[0]
                normalized = self._normalize_host(domain_part)
                if normalized and '.' in normalized:
                    temp_set.add(normalized)
            return temp_set

        def _extract_download_url(payload: Any) -> Optional[str]:
            if isinstance(payload, dict):
                for key in ("download", "download_url", "csv", "csv_url", "url"):
                    value = payload.get(key)
                    if isinstance(value, str) and value.startswith("http"):
                        return value
                for key, value in payload.items():
                    if "download" in str(key).lower() and isinstance(value, str) and value.startswith("http"):
                        return value
                for value in payload.values():
                    candidate = _extract_download_url(value)
                    if candidate:
                        return candidate
                return None
            if isinstance(payload, list):
                for item in payload:
                    candidate = _extract_download_url(item)
                    if candidate:
                        return candidate
            return None

        def _decode_bytes(blob: bytes) -> str:
            for encoding in ("utf-8-sig", "utf-8", "latin-1"):
                try:
                    return blob.decode(encoding)
                except Exception:
                    continue
            return ""

        def _extract_lines_from_zip(blob: bytes) -> List[str]:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                names = zf.namelist()
                if not names:
                    return []
                csv_candidates = [name for name in names if name.lower().endswith(".csv")]
                selected = csv_candidates[0] if csv_candidates else names[0]
                with zf.open(selected) as file_obj:
                    text = _decode_bytes(file_obj.read())
            return text.splitlines()

        async def _fetch_one(source: str) -> Set[str]:
            async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
                response = await client.get(source)
                response.raise_for_status()

                content_type = (response.headers.get("content-type") or "").lower()
                if "tranco-list.eu/api/lists/" in source or "application/json" in content_type:
                    try:
                        payload = response.json()
                    except Exception:
                        payload = {}
                    download_url = _extract_download_url(payload)
                    if download_url:
                        response = await client.get(download_url)
                        response.raise_for_status()
                        content_type = (response.headers.get("content-type") or "").lower()

            raw_blob = response.content
            source_l = source.lower()
            is_zip = source_l.endswith(".zip") or "zip" in content_type or raw_blob.startswith(b"PK")
            if is_zip:
                lines = await asyncio.to_thread(_extract_lines_from_zip, raw_blob)
            else:
                lines = response.text.splitlines()

            if lines and ('rank' in lines[0].lower() or 'domain' in lines[0].lower()):
                lines = lines[1:]
            return await asyncio.to_thread(_process_lines, lines)

        last_error = None
        combined_set: Set[str] = set()
        for source in sources:
            try:
                new_set = await _fetch_one(source)
                if not new_set:
                    source_status[source] = "EMPTY"
                    continue
                combined_set.update(new_set)
                source_status[source] = f"OK ({len(new_set)})"
                print(f"Trusted source loaded: {source} ({len(new_set)} domains)")
            except Exception as e:
                last_error = e
                source_status[source] = f"FAILED: {e.__class__.__name__}"
                print(f"Refresh source failed ({source}): {e}")

        if combined_set:
            def _save_and_update(updated_set: Set[str]):
                self.trusted_global = updated_set
                self._save_json_set(self.TRUSTED_CACHE, self.trusted_global)
                self._rebuild_global_index()
                self._clear_result_cache()

            await asyncio.to_thread(_save_and_update, combined_set)
            with self.health_lock:
                self.health_status["global_cache"] = f"OK ({len(combined_set)})"
                self.health_status["trusted_last_refresh"] = _now_str()
                self.health_status["source_status"] = {
                    **self.health_status.get("source_status", {}),
                    "trusted": source_status,
                }
            print(f"Refreshed global list from {len(sources)} source(s): {len(self.trusted_global)} domains.")
            return

        if last_error is not None:
            with self.health_lock:
                self.health_status["global_cache"] = f"FAILED: {last_error.__class__.__name__}"
                self.health_status["source_status"] = {
                    **self.health_status.get("source_status", {}),
                    "trusted": source_status,
                }

    def _parse_threat_feed_text(self, content: str) -> Set[str]:
        out: Set[str] = set()
        token_pattern = re.compile(r"(https?://[^\s,;]+|[a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)
        for raw in (content or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Accept plain domains, URLs, CSV columns and adblock-style rows.
            cleaned = line.replace("||", " ").replace("^", " ")
            candidates = token_pattern.findall(cleaned)
            if not candidates:
                candidates = [cleaned]
            for token in candidates:
                host = self._normalize_host(token.strip())
                if host and "." in host:
                    out.add(host)
        return out

    async def _refresh_threat_feed(self):
        if not self.THREAT_FEED_SOURCES:
            return
        combined: Set[str] = set()
        source_status: Dict[str, str] = {}
        for source in self.THREAT_FEED_SOURCES:
            try:
                async with httpx.AsyncClient(timeout=35) as client:
                    resp = await client.get(source)
                    resp.raise_for_status()
                parsed = await asyncio.to_thread(self._parse_threat_feed_text, resp.text)
                if parsed:
                    combined.update(parsed)
                    source_status[source] = f"OK ({len(parsed)})"
                    print(f"Threat feed loaded from {source}: {len(parsed)} domains")
                else:
                    source_status[source] = "EMPTY"
            except Exception as e:
                source_status[source] = f"FAILED: {e.__class__.__name__}"
                print(f"Threat feed source failed ({source}): {e}")

        if combined:
            with self.list_lock:
                self.threat_feed = combined
            self._clear_result_cache()
            print(f"Threat feed refreshed: {len(self.threat_feed)} domains")
            with self.health_lock:
                self.health_status["threat_feed_status"] = f"OK ({len(self.threat_feed)})"
                self.health_status["threat_last_refresh"] = _now_str()
                self.health_status["source_status"] = {
                    **self.health_status.get("source_status", {}),
                    "threat": source_status,
                }
        elif source_status:
            with self.health_lock:
                self.health_status["threat_feed_status"] = "FAILED"
                self.health_status["source_status"] = {
                    **self.health_status.get("source_status", {}),
                    "threat": source_status,
                }

    async def _check_google_safe_browsing(self, target_url: str) -> Optional[Tuple[bool, str]]:
        """
        Returns:
          - (True, threat_type) when matched
          - (False, "") when checked and clean
          - None when not configured or request failed
        """
        if not self.gsb_api_key:
            return None

        normalized_url = _normalize_url_for_parse(target_url)
        cached = self._gsb_cache_get(normalized_url)
        if cached is not None:
            return cached

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": normalized_url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.gsb_timeout_sec) as client:
                resp = await client.post(endpoint, json=payload)
            if resp.status_code >= 400:
                return None
            data = resp.json()
            matches = data.get("matches", []) if isinstance(data, dict) else []
            if matches:
                threat_type = str(matches[0].get("threatType", "UNKNOWN"))
                self._gsb_cache_set(normalized_url, True, threat_type)
                return True, threat_type
            self._gsb_cache_set(normalized_url, False, "")
            return False, ""
        except Exception:
            return None

    async def _trusted_refresher_worker(self):
        if not self.trusted_global or len(self.trusted_global) < 100: await self._refresh_trusted_global()
        await self._refresh_threat_feed()
        while True:
            await asyncio.sleep(6 * 60 * 60)
            await self._refresh_trusted_global()
            await self._refresh_threat_feed()  # Refresh every 6 hours.

    # Public mutation helpers used by routes and admin actions.
    async def add_user_trusted(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        updated = False
        with self.list_lock:
            if host not in self.user_trusted:
                self.user_trusted.add(host)
                updated = True
        if updated:
            if self.store:
                await self.store.set_list("user_trusted", sorted(self.user_trusted))
            self._clear_result_cache()
        return updated

    async def remove_user_trusted(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        updated = False
        with self.list_lock:
            if host in self.user_trusted:
                self.user_trusted.remove(host)
                updated = True
        if updated:
            if self.store:
                await self.store.set_list("user_trusted", sorted(self.user_trusted))
            self._clear_result_cache()
        return updated

    # Add a domain or wildcard pattern to the manual blacklist.
    async def add_user_blacklist(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        updated = False
        with self.list_lock:
            if host not in self.user_blacklist:
                self.user_blacklist.add(host)
                updated = True
        if updated:
            if self.store:
                await self.store.set_list("user_blacklist", sorted(self.user_blacklist))
            self._clear_result_cache()
        return updated

    # Remove a domain or wildcard pattern from the manual blacklist.
    async def remove_user_blacklist(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        updated = False
        with self.list_lock:
            if host in self.user_blacklist:
                self.user_blacklist.remove(host)
                updated = True
        if updated:
            if self.store:
                await self.store.set_list("user_blacklist", sorted(self.user_blacklist))
            self._clear_result_cache()
        return updated

    # Snapshot lists for templates and status endpoints.
    def get_list_data(self):
        self._cleanup_expired_temp_trusted()
        with self.list_lock:
            return {
                "global_count": len(self.trusted_global),
                "user_trusted": sorted(list(self.user_trusted)),
                "user_blacklist": sorted(list(self.user_blacklist)),
                "temp_user_trusted": self.get_temp_trusted_items(limit=500),
            }

    def get_reports(self, limit: int = 250) -> List[Dict[str, Any]]:
        with self.reports_lock: return self.reports[:limit]

    def add_report(self, url: str, domain: str, probability: int, similar_to: Optional[str], reasons: List[str]):
        report = {"url": url, "domain": domain, "probability": probability, "similar_to": similar_to, "reasons": reasons, "time": _now_str()}
        with self.reports_lock: self.reports.insert(0, report); self.reports = self.reports[:1000]  # Keep the newest 1000 reports.
        self._append_domain_timeline(
            domain,
            probability=int(probability or 0),
            is_phishing=True,
            reason=(reasons[0] if reasons else "report"),
        )

    def add_scan_history(self, entry: Dict[str, Any]):
        with self.scan_history_lock:
            self.scan_history.insert(0, entry)
            self.scan_history = self.scan_history[:500]

    def get_scan_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.scan_history_lock:
            return self.scan_history[:limit]

    def _fingerprint_signature(self, fp: Dict[str, Any]) -> str:
        keys = [
            "scheme", "tld", "subdomain_count", "has_ip", "has_punycode",
            "has_unicode", "has_userinfo", "keyword_hits", "port", "path_depth",
        ]
        values = [str(fp.get(k, "")) for k in keys]
        return "|".join(values)

    def _build_domain_fingerprint(self, target_url: str, host: str, indicators: List[str]) -> Dict[str, Any]:
        normalized_url = _normalize_url_for_parse(target_url)
        parsed = urllib.parse.urlparse(normalized_url)
        labels = [p for p in (host or "").split(".") if p]
        path = parsed.path or ""
        path_tokens = [p for p in path.split("/") if p]
        fp = {
            "scheme": (parsed.scheme or "").lower(),
            "tld": labels[-1] if labels else "",
            "subdomain_count": max(0, len(labels) - 2),
            "host_len": len(host or ""),
            "sld_len": len(self._extract_sld(host or "")),
            "has_ip": int("IP address in URL" in indicators),
            "has_punycode": int("Punycode domain" in indicators),
            "has_unicode": int("Unicode in domain" in indicators),
            "has_userinfo": int("Userinfo (@) in URL" in indicators),
            "keyword_hits": sum(1 for k in SUSPICIOUS_KEYWORDS if k in normalized_url.lower()),
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "path_depth": len(path_tokens),
        }
        return fp

    def _update_domain_fingerprint(self, host: str, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        sig = self._fingerprint_signature(fingerprint)
        now = _now_str()
        with self.timeline_lock:
            prev = self.domain_fingerprints.get(host)
            if not prev:
                state = {
                    "host": host,
                    "signature": sig,
                    "fingerprint": fingerprint,
                    "first_seen": now,
                    "last_seen": now,
                    "drift_count": 0,
                    "last_drift_at": None,
                }
                self.domain_fingerprints[host] = state
                return {"drifted": False, "drift_score": 0, "state": state}

            drifted = prev.get("signature") != sig
            drift_count = int(prev.get("drift_count", 0))
            drift_score = 0
            if drifted:
                drift_count += 1
                drift_score = min(18, 6 + min(12, drift_count * 2))
                prev["last_drift_at"] = now
            prev["signature"] = sig
            prev["fingerprint"] = fingerprint
            prev["last_seen"] = now
            prev["drift_count"] = drift_count
            return {"drifted": drifted, "drift_score": drift_score, "state": prev}

    def _append_domain_timeline(self, host: str, probability: int, is_phishing: bool, reason: str):
        if not host:
            return
        entry = {
            "time": _now_str(),
            "probability": int(max(0, min(100, probability))),
            "is_phishing": bool(is_phishing),
            "reason": reason[:120] if reason else "",
        }
        with self.timeline_lock:
            rows = self.domain_timeline.setdefault(host, [])
            rows.append(entry)
            if len(rows) > 720:
                self.domain_timeline[host] = rows[-720:]

    def get_domain_timeline(self, host: str, hours: int = 168, limit: int = 300) -> List[Dict[str, Any]]:
        host = self._normalize_host(host)
        if not host:
            return []
        cutoff = datetime.utcnow() - timedelta(hours=max(1, min(hours, 24 * 30)))
        with self.timeline_lock:
            rows = list(self.domain_timeline.get(host, []))
        out: List[Dict[str, Any]] = []
        for row in rows:
            dt = _parse_time(str(row.get("time", "")))
            if dt and dt < cutoff:
                continue
            out.append(row)
        return out[-max(5, min(limit, 1000)):]

    def get_fingerprint_state(self, host: str) -> Optional[Dict[str, Any]]:
        host = self._normalize_host(host)
        if not host:
            return None
        with self.timeline_lock:
            state = self.domain_fingerprints.get(host)
            return copy.deepcopy(state) if state else None

    def get_campaign_clusters(self, hours: int = 72, min_size: int = 2) -> List[Dict[str, Any]]:
        cutoff = datetime.utcnow() - timedelta(hours=max(1, min(hours, 24 * 14)))
        with self.reports_lock:
            rows = list(self.reports[:2000])
        clusters: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            dt = _parse_time(str(row.get("time", "")))
            if dt and dt < cutoff:
                continue
            domain = self._normalize_host(str(row.get("domain", "")))
            if not domain:
                continue
            tld = self._extract_tld(domain)
            reasons = " ".join(str(x).lower() for x in row.get("reasons", [])[:4])
            keyword = "generic"
            for k in sorted(SUSPICIOUS_KEYWORDS):
                if k in domain or k in reasons:
                    keyword = k
                    break
            similar = self._normalize_host(str(row.get("similar_to") or ""))
            key = f"{tld}|{keyword}|{similar or '-'}"
            c = clusters.setdefault(key, {
                "cluster_id": key,
                "tld": tld,
                "keyword": keyword,
                "similar_to": similar or None,
                "count": 0,
                "max_probability": 0,
                "domains": set(),
                "last_seen": row.get("time", ""),
            })
            c["count"] += 1
            c["max_probability"] = max(c["max_probability"], int(row.get("probability", 0) or 0))
            c["domains"].add(domain)
            c["last_seen"] = row.get("time", c["last_seen"])

        out: List[Dict[str, Any]] = []
        for c in clusters.values():
            if c["count"] < max(2, min_size):
                continue
            out.append({
                "cluster_id": c["cluster_id"],
                "tld": c["tld"],
                "keyword": c["keyword"],
                "similar_to": c["similar_to"],
                "count": c["count"],
                "max_probability": c["max_probability"],
                "domains": sorted(list(c["domains"]))[:20],
                "last_seen": c["last_seen"],
            })
        out.sort(key=lambda x: (x["count"], x["max_probability"]), reverse=True)
        return out[:40]

    def get_feedback_bias(self, host: str) -> Dict[str, int]:
        host = self._normalize_host(host)
        if not host:
            return {"fp": 0, "fn": 0}
        with self.timeline_lock:
            direct = self.feedback_domain_bias.get(host)
            if direct:
                return {"fp": int(direct.get("fp", 0)), "fn": int(direct.get("fn", 0))}
            labels = [p for p in host.split(".") if p]
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                d = self.feedback_domain_bias.get(parent)
                if d:
                    return {"fp": int(d.get("fp", 0)), "fn": int(d.get("fn", 0))}
        return {"fp": 0, "fn": 0}

    def apply_feedback_bias(self, host: str, probability: int) -> Tuple[int, str]:
        bias = self.get_feedback_bias(host)
        fp = int(bias.get("fp", 0))
        fn = int(bias.get("fn", 0))
        adjustment = 0
        if fp > fn and fp >= 3:
            adjustment = -min(16, 2 + (fp - fn) * 2)
        elif fn > fp and fn >= 2:
            adjustment = min(18, 3 + (fn - fp) * 2)
        adjusted = int(max(0, min(100, int(probability) + adjustment)))
        note = ""
        if adjustment != 0:
            note = f"Feedback Bias: {adjustment:+d}% (fp={fp}, fn={fn})"
        return adjusted, note

    def _update_feedback_bias_from_feedback(self, row: Dict[str, Any]):
        host = self._normalize_host(str(row.get("domain") or row.get("url") or ""))
        if not host:
            return
        label = str(row.get("label", "")).strip().lower()
        pred_is_phish = bool(row.get("predicted_is_phishing", False))
        with self.timeline_lock:
            bias = self.feedback_domain_bias.setdefault(host, {"fp": 0, "fn": 0})
            if label == "not_phishing" and pred_is_phish:
                bias["fp"] = int(bias.get("fp", 0)) + 1
            elif label == "phishing" and not pred_is_phish:
                bias["fn"] = int(bias.get("fn", 0)) + 1

    def get_honey_tokens_list(self) -> List[Dict[str, Any]]:
        with self.timeline_lock:
            rows = [copy.deepcopy(v) for v in self.honey_tokens.values()]
        rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return rows[:200]

    async def create_honey_token(self, created_by: str, label: str = "training") -> Dict[str, Any]:
        token = uuid.uuid4().hex[:16]
        row = {
            "token": token,
            "label": (label or "training")[:80],
            "created_by": (created_by or "")[:64],
            "created_at": _now_str(),
            "hits": 0,
            "last_hit": "",
        }
        with self.timeline_lock:
            self.honey_tokens[token] = row
        if self.store:
            await self.store.set_honey_tokens(self.get_honey_tokens_list())
        return row

    async def mark_honey_hit(self, token: str, source: str, ip: str):
        token = str(token or "").strip()
        if not token:
            return
        now = _now_str()
        with self.timeline_lock:
            row = self.honey_tokens.get(token)
            if row:
                row["hits"] = int(row.get("hits", 0)) + 1
                row["last_hit"] = now
            self.honey_events.insert(0, {
                "time": now,
                "token": token,
                "source": source[:120],
                "ip": ip,
                "known_token": bool(row),
            })
            self.honey_events = self.honey_events[:1000]
        if self.store and row:
            await self.store.set_honey_tokens(self.get_honey_tokens_list())

    def get_honey_events(self, limit: int = 300) -> List[Dict[str, Any]]:
        with self.timeline_lock:
            return list(self.honey_events[:max(1, min(limit, 2000))])

    def get_dashboard_metrics(self, hours: int = 24) -> Dict[str, Any]:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=max(1, min(hours, 168)))

        with self.reports_lock:
            reports = list(self.reports[:1500])
        with self.scan_history_lock:
            scan_rows = list(self.scan_history[:1500])

        report_recent: List[Dict[str, Any]] = []
        domain_counter: Dict[str, int] = {}
        for row in reports:
            dt = _parse_time(str(row.get("time", "")))
            if dt and dt < cutoff:
                continue
            report_recent.append(row)
            d = str(row.get("domain", "")).strip().lower()
            if d:
                domain_counter[d] = domain_counter.get(d, 0) + 1

        scans_recent = []
        for row in scan_rows:
            dt = _parse_time(str(row.get("time", "")))
            if dt and dt < cutoff:
                continue
            scans_recent.append(row)

        phishing_total = int(sum(int(r.get("phishing", 0) or 0) for r in scans_recent))
        safe_total = int(sum(int(r.get("safe", 0) or 0) for r in scans_recent))
        scan_total = int(sum(int(r.get("total", 0) or 0) for r in scans_recent))
        hit_rate = round((phishing_total / scan_total) * 100, 2) if scan_total > 0 else 0.0

        top_domains = sorted(
            [{"domain": k, "count": v} for k, v in domain_counter.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:8]

        return {
            "window_hours": hours,
            "reports_count": len(report_recent),
            "scan_total": scan_total,
            "scan_safe": safe_total,
            "scan_phishing": phishing_total,
            "hit_rate_percent": hit_rate,
            "top_domains": top_domains,
            "recent_reports": report_recent[:30],
        }

    # Clear in-memory reports after an admin confirms purge.
    def purge_reports(self):
        with self.reports_lock:
            self.reports = []
            print("All reports purged by admin.")

    async def set_server_sensitivity(self, sensitivity: int):
        with self.sensitivity_lock:
            self.server_sensitivity = max(50, min(100, sensitivity))
        self._clear_result_cache()
        if self.store:
            await self.store.set_server_sensitivity(self.server_sensitivity)

    def get_health_status(self) -> Dict[str, Any]:
        with self.health_lock:
            self.health_status["uptime_seconds"] = int(time.time() - self.health_status.get("last_ping", time.time()))
            self.health_status["ml_model"] = "OK" if self.ml_model.is_healthy else "FAILED"
            self.health_status["threat_feed_count"] = len(self.threat_feed)
            self.health_status["gsb_enabled"] = bool(self.gsb_api_key)
            self.health_status["temporary_trusted_count"] = len(self.temp_user_trusted)
            return self.health_status.copy()

    # Main detector logic. Keep thresholds conservative so trusted domains are not flagged casually.
    async def check_link(
        self,
        target_url: str,
        user_sensitivity: Optional[int] = None,
        lite: bool = False,
        user_team: Optional[str] = None,
    ) -> Dict[str, Any]:
        target_host = self._normalize_host(target_url)
        if not target_host:
            invalid = {"is_phishing": False, "domain": "", "probability": 0, "reasons": ["Invalid host"], "indicators": []}
            return self._to_lite_result(invalid) if lite else invalid

        try:
            effective_sensitivity = int(user_sensitivity) if user_sensitivity is not None else int(self.server_sensitivity)
        except Exception:
            effective_sensitivity = int(self.server_sensitivity)
        effective_sensitivity = max(50, min(100, effective_sensitivity))
        team = _normalize_team(user_team)
        effective_sensitivity = max(50, min(100, effective_sensitivity + int(TEAM_SENSITIVITY_OFFSET.get(team, 0))))
        # Higher sensitivity lowers threshold, but keep enough margin to reduce false positives.
        phish_threshold = int(round(max(58, min(92, 110 - (effective_sensitivity * 0.5)))))

        cache_key = self._cache_key(target_host, effective_sensitivity)
        cached = self._cache_get(cache_key)
        if cached:
            return self._to_lite_result(cached) if lite else cached

        self._cleanup_expired_temp_trusted()
        with self.list_lock:
            in_blacklist, matched_blacklist = self._host_or_parent_in_set(target_host, self.user_blacklist)
            if not in_blacklist:
                in_blacklist, matched_blacklist = self._host_matches_patterns(target_host, self.user_blacklist)

            in_user_trusted, matched_user_trusted = self._host_or_parent_in_set(target_host, self.user_trusted)
            if not in_user_trusted:
                in_user_trusted, matched_user_trusted = self._host_matches_patterns(target_host, self.user_trusted)

            in_global_trusted, matched_global_trusted = self._host_or_parent_in_set(target_host, self.trusted_global)
            in_threat_feed, matched_threat = self._host_or_parent_in_set(target_host, self.threat_feed)
            temp_trusted_row = self.temp_user_trusted.get(target_host)

        if in_blacklist:
            blacklisted = {
                "is_phishing": True,
                "domain": target_host,
                "probability": 100,
                "similar_to": None,
                "reasons": [f"Force blocked by blacklist ({matched_blacklist})"] if matched_blacklist else ["Force blocked by blacklist"],
                "indicators": [],
                "sensitivity": effective_sensitivity,
                "user_sensitivity": user_sensitivity,
                "team": team,
                "threshold": phish_threshold,
            }
            self.add_report(target_url, target_host, 100, "N/A", ["Force blocked by blacklist"])
            self._cache_set(cache_key, blacklisted)
            return self._to_lite_result(blacklisted) if lite else blacklisted

        if in_threat_feed:
            threat_hit = {
                "is_phishing": True,
                "domain": target_host,
                "probability": 99,
                "similar_to": None,
                "reasons": [f"Known malicious domain (threat feed: {matched_threat})"] if matched_threat else ["Known malicious domain (threat feed)"],
                "indicators": [],
                "sensitivity": effective_sensitivity,
                "user_sensitivity": user_sensitivity,
                "team": team,
                "threshold": phish_threshold,
            }
            self.add_report(target_url, target_host, 99, "N/A", threat_hit["reasons"])
            self._cache_set(cache_key, threat_hit)
            return self._to_lite_result(threat_hit) if lite else threat_hit

        if in_user_trusted or in_global_trusted:
            trusted_result = {
                "is_phishing": False,
                "domain": target_host,
                "probability": 0,
                "similar_to": None,
                "reasons": [f"Trusted by user ({matched_user_trusted})"] if in_user_trusted else [f"Trusted globally ({matched_global_trusted})"],
                "indicators": [],
                "sensitivity": effective_sensitivity,
                "user_sensitivity": user_sensitivity,
                "team": team,
                "threshold": phish_threshold,
            }
            self._cache_set(cache_key, trusted_result)
            return self._to_lite_result(trusted_result) if lite else trusted_result

        if temp_trusted_row:
            trusted_temp = {
                "is_phishing": False,
                "domain": target_host,
                "probability": 0,
                "similar_to": None,
                "reasons": [f"Temporarily trusted until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(temp_trusted_row.get('expires_at', 0))))}"],
                "indicators": [],
                "sensitivity": effective_sensitivity,
                "user_sensitivity": user_sensitivity,
                "team": team,
                "threshold": phish_threshold,
            }
            self._cache_set(cache_key, trusted_temp)
            return self._to_lite_result(trusted_temp) if lite else trusted_temp

        scoring_indicators = _url_indicators(target_url, target_host)
        indicators = [] if lite else list(scoring_indicators)
        heuristic_risk = self._heuristic_risk(target_url, target_host, scoring_indicators)
        fingerprint = self._build_domain_fingerprint(target_url, target_host, scoring_indicators)
        candidates = self._candidate_domains(target_host)
        brand_boost, brand_like_domain = self._brand_injection_signal(target_host, candidates)

        try:
            def _blocking_check(
                sensitivity_level: int,
                threshold_level: int,
                heuristic_score: int,
                brand_score: int,
                brand_hint_domain: Optional[str],
            ):
                max_similarity = 0
                most_similar_trusted: Optional[str] = None

                if candidates:
                    if FUZZY_LIB == 'rapidfuzz' and rf_process:
                        best = rf_process.extractOne(
                            target_host,
                            candidates,
                            scorer=fuzz.WRatio,
                            score_cutoff=45,
                        )
                        if best:
                            most_similar_trusted = best[0]
                            max_similarity = int(best[1])
                    else:
                        for trusted_host in candidates:
                            sim = self._similarity(target_host, trusted_host)
                            if sim < 45:
                                continue
                            if sim > max_similarity:
                                max_similarity = sim
                                most_similar_trusted = trusted_host

                is_phishing = False
                probability = 0
                reasons: List[str] = []

                if max_similarity >= 45 and most_similar_trusted:
                    ml_risk_score = self.ml_model.predict_risk(target_host, most_similar_trusted, max_similarity)
                    sensitivity_multiplier = 0.5 + (sensitivity_level - 50) * 0.02
                    adjusted_risk_score = min(1.0, ml_risk_score * sensitivity_multiplier)
                    remaining_gap = 100 - max_similarity
                    boost_to_add = remaining_gap * adjusted_risk_score
                    heuristic_boost = min(20.0, heuristic_score * 0.35)
                    brand_bonus = min(18.0, float(brand_score))
                    probability = int(round(max_similarity + boost_to_add + heuristic_boost + brand_bonus))
                    probability = max(0, min(100, probability))

                    if probability >= threshold_level:
                        is_phishing = True

                    reasons.append(f"Risk Score: {probability}%")
                    if not lite:
                        reasons.append(f"Fuzzy Match: {max_similarity}% (to {most_similar_trusted})")
                        reasons.append(f"ML Risk Score: {ml_risk_score:.2f} (Gap-Fill Boost: +{boost_to_add:.1f}%)")
                        reasons.append(f"Heuristic Boost: +{heuristic_boost:.1f}%")
                        if brand_score > 0 and brand_hint_domain:
                            reasons.append(f"Brand Injection Boost: +{brand_bonus:.1f}% (brand: {brand_hint_domain})")
                        if is_phishing:
                            reasons.append(f"Final ({probability}%) >= Threshold ({threshold_level}%)")
                        else:
                            reasons.append(f"Final ({probability}%) < Threshold ({threshold_level}%)")
                else:
                    # No strong brand similarity: rely on heuristic score.
                    probability = int(max(0, min(100, heuristic_score + brand_score)))
                    if probability >= threshold_level:
                        is_phishing = True
                    if brand_score > 0 and brand_hint_domain and not most_similar_trusted:
                        most_similar_trusted = brand_hint_domain
                    if not lite:
                        reasons.append("No trusted domain similar enough (>45%) found.")
                        reasons.append(f"Heuristic Risk: {heuristic_score}%")
                        if brand_score > 0 and brand_hint_domain:
                            reasons.append(f"Brand token matched with extra suspicious terms: {brand_hint_domain} (+{brand_score}%)")

                return is_phishing, probability, most_similar_trusted, reasons

            is_phishing, probability, most_similar_trusted, reasons = await asyncio.to_thread(
                _blocking_check, effective_sensitivity, phish_threshold, heuristic_risk, brand_boost, brand_like_domain
            )

            fp_state = self._update_domain_fingerprint(target_host, fingerprint)
            drift_score = int(fp_state.get("drift_score", 0) or 0)
            if drift_score > 0:
                probability = max(0, min(100, int(probability) + drift_score))
                if not lite:
                    reasons.append(
                        f"Fingerprint Drift: +{drift_score}% (changes={fp_state['state'].get('drift_count', 0)})"
                    )

            probability, bias_note = self.apply_feedback_bias(target_host, probability)
            if bias_note and not lite:
                reasons.append(bias_note)
            is_phishing = bool(probability >= phish_threshold)

            # Optional high-confidence external check for borderline suspicious URLs.
            if (not lite) and (not is_phishing) and probability >= max(35, phish_threshold - 8):
                gsb_result = await self._check_google_safe_browsing(target_url)
                if gsb_result and gsb_result[0]:
                    is_phishing = True
                    probability = max(probability, 97)
                    reasons.append(f"Google Safe Browsing match: {gsb_result[1]}")

            if indicators:
                reasons.extend([f"Indicator: {i}" for i in indicators])

            full_result = {
                "is_phishing": is_phishing,
                "domain": target_host,
                "probability": probability,
                "similar_to": most_similar_trusted,
                "reasons": reasons,
                "indicators": indicators,
                "sensitivity": effective_sensitivity,
                "user_sensitivity": user_sensitivity,
                "team": team,
                "threshold": phish_threshold,
            }
            if not lite:
                full_result["fingerprint"] = fingerprint
                full_result["fingerprint_state"] = {
                    "drift_count": fp_state["state"].get("drift_count", 0),
                    "last_drift_at": fp_state["state"].get("last_drift_at"),
                }

            if is_phishing:
                self.add_report(target_url, target_host, probability, most_similar_trusted, reasons or [f"Risk Score: {probability}%"])
            elif probability >= 25:
                self._append_domain_timeline(
                    target_host,
                    probability=int(probability),
                    is_phishing=False,
                    reason=(reasons[0] if reasons else "risk"),
                )

            self._cache_set(cache_key, full_result)
            return self._to_lite_result(full_result) if lite else full_result
        except HTTPException:
            raise
        except Exception as e:
            print(f"\n[CRITICAL ERROR] Check failed for URL: {target_url}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail={"error": "Processing error", "message": str(e)})

# Initialize the detector core.
detector = PhishDetector()
check_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_CHECK_PER_MIN, 60)
batch_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_BATCH_PER_MIN, 60)
login_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_LOGIN_PER_5MIN, 5 * 60)
scan_rate_limiter = SlidingWindowRateLimiter(max(20, RATE_LIMIT_BATCH_PER_MIN * 2), 60)

def _enforce_rate_limit(request: Request, limiter: SlidingWindowRateLimiter, scope: str, cost: int = 1):
    key = f"{scope}:{_client_ip(request)}"
    allowed, retry_after = limiter.allow(key, cost=cost)
    if allowed:
        return
    raise HTTPException(
        status_code=429,
        detail=f"Too many requests for {scope}. Retry later.",
        headers={"Retry-After": str(retry_after)},
    )

def _session_actor(request: Request) -> str:
    username = request.session.get("username") if hasattr(request, "session") else None
    if not username:
        return "anonymous"
    if request.session.get("is_admin"):
        return f"admin:{username}"
    return f"user:{username}"

async def _audit(request: Request, action: str, target: str = "", meta: Optional[Dict[str, Any]] = None):
    global mongo_store
    if not mongo_store:
        return
    try:
        await mongo_store.add_audit_log(
            actor=_session_actor(request),
            action=action,
            target=target,
            meta=meta,
            ip=_client_ip(request),
        )
    except Exception:
        # Audit logging must never break the request path.
        pass

@app.on_event("startup")
async def startup_event():
    global mongo_store, RANK_CAPS_OVERRIDES
    if not MONGO_URI:
        raise RuntimeError("PHISH_MONGO_URI is required for MongoDB storage.")
    mongo_store = MongoStore(MONGO_URI, MONGO_DB_NAME)
    await mongo_store.ensure_defaults()
    overrides = await mongo_store.get_rank_caps_overrides()
    RANK_CAPS_OVERRIDES = _sanitize_caps_overrides(overrides)
    await detector.load_from_store(mongo_store)
    print("FastAPI Startup: Launching async trusted list refresher.")
    asyncio.create_task(detector._trusted_refresher_worker())

# Routing and authentication dependencies.
async def require_authenticated(request: Request):
    """Dependency to check if user is logged in (admin or normal)."""
    if not request.session.get("authenticated"):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Authentication required",
            headers={"Location": app.url_path_for("login")},
        )
    return request.session

async def require_admin(request: Request):
    """Dependency to check if user is logged in AND is an admin."""
    session = await require_authenticated(request)
    if not session.get("is_admin"):
        # A signed-in normal user can still open the login page and switch into an admin session.
        print(f"Admin access denied for user: {session.get('username')}. Redirecting to login.")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Admin access required",
            headers={"Location": app.url_path_for("login")},
        )
    return session.get("username")


# Health/status endpoint used by the app, extension and uptime checks.
@app.get("/ping")
async def ping():
    health = detector.get_health_status()
    list_data = detector.get_list_data()
    return {"status": "ok",
            "trusted_count": list_data["global_count"],
            "user_trusted_count": len(list_data["user_trusted"]),
            "user_blacklist_count": len(list_data["user_blacklist"]),
            "temp_trusted_count": len(list_data.get("temp_user_trusted", [])),
            "threat_feed_count": len(detector.threat_feed),
            "gsb_enabled": bool(detector.gsb_api_key),
            "server_sensitivity": detector.server_sensitivity,
            "fuzzy_lib": FUZZY_LIB,
            "health": health}

# Core link checking API.
@app.post("/check_link")
async def check_link_api(request: Request):
    _enforce_rate_limit(request, check_rate_limiter, "check_link")
    try:
        data = await request.json()
        url = data.get("url")
        user_sensitivity = data.get("user_sensitivity")
        user_team = data.get("user_team")
        lite = bool(data.get("lite", False))
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not url: return JSONResponse({"error": "URL not provided"}, status_code=400)
    try:
        result = await detector.check_link(url, user_sensitivity, lite=lite, user_team=user_team)
        return JSONResponse(result)
    except HTTPException as he:
        return JSONResponse(he.detail, status_code=he.status_code, headers=getattr(he, "headers", None))
    except Exception: return JSONResponse({"is_phishing": False, "error": "Internal API error"}, status_code=500)

@app.post("/check_batch")
async def check_batch_api(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    items = data.get("items")
    default_sensitivity = data.get("user_sensitivity")
    default_team = data.get("user_team")
    lite = bool(data.get("lite", False))

    if not isinstance(items, list) or not items:
        return JSONResponse({"error": "items must be a non-empty list"}, status_code=400)
    if len(items) > MAX_BATCH_ITEMS:
        return JSONResponse({"error": f"Batch too large (max {MAX_BATCH_ITEMS})"}, status_code=400)

    _enforce_rate_limit(request, batch_rate_limiter, "check_batch", cost=max(1, len(items) // 8))

    sem = asyncio.Semaphore(max(1, CHECK_BATCH_CONCURRENCY))
    async def _run_one(item: Dict[str, Any]):
        url = item.get("url") if isinstance(item, dict) else None
        if not url:
            return {"is_phishing": False, "domain": "", "probability": 0, "error": "missing_url"}
        sensitivity = item.get("user_sensitivity", default_sensitivity) if isinstance(item, dict) else default_sensitivity
        team = item.get("user_team", default_team) if isinstance(item, dict) else default_team
        async with sem:
            return await detector.check_link(url, sensitivity, lite=lite, user_team=team)

    try:
        results = await asyncio.gather(*[_run_one(i) for i in items], return_exceptions=True)
        normalized = []
        for res in results:
            if isinstance(res, Exception):
                normalized.append({"is_phishing": False, "domain": "", "probability": 0, "error": "internal_error"})
            else:
                normalized.append(res)
        return JSONResponse({"results": normalized, "count": len(normalized)})
    except HTTPException as he:
        return JSONResponse(he.detail, status_code=he.status_code, headers=getattr(he, "headers", None))
    except Exception:
        return JSONResponse({"error": "Internal batch error"}, status_code=500)

async def _scan_links(
    text: str,
    include_redirects: bool,
    caps: Dict[str, Any],
    actor: str = "",
    user_team: str = DEFAULT_TEAM,
) -> Dict[str, Any]:
    if include_redirects and not caps.get("panel", {}).get("redirect_chain", False):
        include_redirects = False

    links = _extract_links(text)
    results = []
    phishing_count = 0
    safe_count = 0
    semaphore = asyncio.Semaphore(max(2, CHECK_BATCH_CONCURRENCY))

    async def _scan_one(url: str):
        try:
            async with semaphore:
                res = await detector.check_link(url, user_team=user_team)
            status = "PHISHING" if res.get("is_phishing") else "SAFE"
            short_reason = _short_reason(res.get("reasons", []))
            chain = await _redirect_chain(url) if include_redirects else []
            return {
                "url": url,
                "domain": res.get("domain"),
                "status": status,
                "probability": res.get("probability", 0),
                "similar_to": res.get("similar_to"),
                "reasons": res.get("reasons", []),
                "indicators": res.get("indicators", []),
                "short_reason": short_reason,
                "redirect_chain": chain,
            }
        except Exception as e:
            return {
                "url": url,
                "domain": "",
                "status": "ERROR",
                "probability": 0,
                "similar_to": None,
                "reasons": [str(e)],
                "short_reason": "Error",
                "indicators": [],
                "redirect_chain": [],
            }

    if links:
        results = await asyncio.gather(*[_scan_one(url) for url in links])

    for item in results:
        if item["status"] == "PHISHING":
            phishing_count += 1
        elif item["status"] == "SAFE":
            safe_count += 1

    history_entry = {
        "time": _now_str(),
        "total": len(results),
        "phishing": phishing_count,
        "safe": safe_count,
        "actor": actor or "",
    }
    detector.add_scan_history(history_entry)

    return {
        "links_found": len(links),
        "summary": history_entry,
        "results": results,
    }

@app.post("/api/scan_text", dependencies=[Depends(require_authenticated)])
async def api_scan_text(request: Request):
    _enforce_rate_limit(request, scan_rate_limiter, "scan_text")
    try:
        data = await request.json()
        text = data.get("text", "")
        include_redirects = bool(data.get("include_redirects", False))
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("scan_text", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)

    result = await _scan_links(
        text,
        include_redirects,
        caps,
        actor=request.session.get("username", ""),
        user_team=_normalize_team(request.session.get("team")),
    )
    await _audit(request, "scan_text", meta={"links_found": result.get("links_found", 0)})
    return JSONResponse(result)

@app.post("/api/scan_file", dependencies=[Depends(require_authenticated)])
async def api_scan_file(request: Request, file: UploadFile = File(...), include_redirects: bool = Form(False)):
    _enforce_rate_limit(request, scan_rate_limiter, "scan_file")
    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("scan_file", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)

    content = await file.read()
    text = ""
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = content.decode(enc)
            break
        except Exception:
            continue
    if not text:
        return JSONResponse({"error": "Unable to decode file"}, status_code=400)

    result = await _scan_links(
        text,
        include_redirects,
        caps,
        actor=request.session.get("username", ""),
        user_team=_normalize_team(request.session.get("team")),
    )
    await _audit(request, "scan_file", target=file.filename or "", meta={"links_found": result.get("links_found", 0)})
    return JSONResponse(result)

@app.get("/api/scan_history", dependencies=[Depends(require_authenticated)])
async def api_scan_history(request: Request):
    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("scan_text", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)
    history = detector.get_scan_history()
    if not session.get("is_admin"):
        username = session.get("username")
        history = [row for row in history if row.get("actor") in ("", username)]
    return JSONResponse({"history": history})

@app.get("/api/export_scan_history", dependencies=[Depends(require_authenticated)])
async def api_export_scan_history(request: Request):
    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("export_history", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)
    history = detector.get_scan_history(limit=10000)
    if not session.get("is_admin"):
        username = session.get("username")
        history = [row for row in history if row.get("actor") in ("", username)]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["time", "actor", "total", "phishing", "safe"])
    for row in history:
        writer.writerow([row.get("time"), row.get("actor", ""), row.get("total"), row.get("phishing"), row.get("safe")])
    csv_data = output.getvalue()
    headers = {"Content-Disposition": "attachment; filename=scan_history.csv"}
    return HTMLResponse(content=csv_data, headers=headers, media_type="text/csv")

@app.post("/api/feedback", dependencies=[Depends(require_authenticated)])
async def api_feedback(request: Request):
    global mongo_store
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    label = str(data.get("label", "")).strip().lower()
    if label not in {"phishing", "not_phishing"}:
        return JSONResponse({"error": "label must be phishing or not_phishing"}, status_code=400)

    url = str(data.get("url", "")).strip()
    if not url:
        return JSONResponse({"error": "url is required"}, status_code=400)

    domain = detector._normalize_host(url)
    payload = {
        "url": url,
        "domain": domain,
        "label": label,
        "source": str(data.get("source", "panel"))[:40],
        "predicted_is_phishing": bool(data.get("predicted_is_phishing", False)),
        "predicted_probability": int(data.get("predicted_probability", 0) or 0),
        "reason": str(data.get("reason", ""))[:300],
        "username": request.session.get("username"),
        "feedback_id": str(uuid.uuid4()),
    }
    feedback_id = payload["feedback_id"]
    if mongo_store:
        feedback_id = await mongo_store.add_feedback(payload)
    detector._update_feedback_bias_from_feedback(payload)
    if mongo_store:
        await mongo_store.set_feedback_domain_bias(detector.feedback_domain_bias)
    await _audit(request, "feedback_submit", target=domain, meta={"label": label, "source": payload["source"]})
    return JSONResponse({"ok": True, "feedback_id": feedback_id})

@app.get("/admin/audit_logs", dependencies=[Depends(require_admin)])
async def admin_audit_logs(limit: int = 200):
    global mongo_store
    if not mongo_store:
        return JSONResponse({"error": "Database not configured"}, status_code=500)
    logs = await mongo_store.get_recent_audit_logs(limit=limit)
    return JSONResponse({"logs": logs})

@app.get("/admin/feedback", dependencies=[Depends(require_admin)])
async def admin_feedback(limit: int = 200, status_filter: str = ""):
    global mongo_store
    if not mongo_store:
        return JSONResponse({"error": "Database not configured"}, status_code=500)
    rows = await mongo_store.get_feedback_recent(limit=limit)
    sf = status_filter.strip().lower()
    if sf and sf != "all":
        rows = [r for r in rows if str(r.get("status", "open")).lower() == sf]
    return JSONResponse({"feedback": rows})

@app.post("/admin/feedback_action", dependencies=[Depends(require_admin)])
async def admin_feedback_action(request: Request):
    global mongo_store
    if not mongo_store:
        return JSONResponse({"error": "Database not configured"}, status_code=500)

    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)

    feedback_id = str(data.get("feedback_id", "")).strip()
    action = str(data.get("action", "")).strip().lower()
    if not feedback_id:
        return JSONResponse({"error": "feedback_id is required"}, status_code=400)
    if action not in {"add_whitelist", "add_blacklist", "dismiss"}:
        return JSONResponse({"error": "invalid action"}, status_code=400)

    item = await mongo_store.get_feedback_item(feedback_id)
    if not item:
        return JSONResponse({"error": "feedback item not found"}, status_code=404)

    domain = detector._normalize_host(str(item.get("domain") or item.get("url") or ""))
    if action in {"add_whitelist", "add_blacklist"} and not domain:
        return JSONResponse({"error": "feedback item has no valid domain"}, status_code=400)
    success = True
    status_value = "resolved_dismissed"
    if action == "add_whitelist":
        success = await detector.add_user_trusted(domain)
        status_value = "resolved_whitelist"
    elif action == "add_blacklist":
        success = await detector.add_user_blacklist(domain)
        status_value = "resolved_blacklist"

    await mongo_store.update_feedback_status(
        feedback_id=feedback_id,
        status_value=status_value,
        resolver=request.session.get("username", "admin"),
        action=action,
    )
    await _audit(request, "feedback_action", target=domain, meta={"action": action, "success": bool(success)})
    return JSONResponse({"ok": True, "success": bool(success), "domain": domain, "action": action})

@app.get("/api/dashboard_metrics", dependencies=[Depends(require_authenticated)])
async def api_dashboard_metrics(request: Request, hours: int = 24):
    _enforce_rate_limit(request, scan_rate_limiter, "dashboard_metrics")
    list_data = detector.get_list_data()
    metrics = detector.get_dashboard_metrics(hours=hours)
    session = request.session
    rank = "admin" if session.get("is_admin") else _normalize_rank(session.get("rank"))
    caps = _get_caps_for_session(session)
    temp_rows = detector.get_temp_trusted_items(limit=200)
    now_ts = int(time.time())
    expiring_24h = [r for r in temp_rows if int(r.get("expires_at", 0)) <= (now_ts + 24 * 3600)]
    return JSONResponse({
        "rank": rank,
        "caps": caps,
        "trusted_count": list_data["global_count"],
        "user_trusted_count": len(list_data["user_trusted"]),
        "user_blacklist_count": len(list_data["user_blacklist"]),
        "temp_trusted_count": len(temp_rows),
        "temp_trusted_expiring_24h": len(expiring_24h),
        "metrics": metrics,
        "health": detector.get_health_status(),
    })

@app.get("/api/recent_reports", dependencies=[Depends(require_authenticated)])
async def api_recent_reports(request: Request, limit: int = 30):
    limit = max(1, min(limit, 200))
    rows = detector.get_reports(limit=limit)
    return JSONResponse({"reports": rows})

@app.get("/api/my_security_summary", dependencies=[Depends(require_authenticated)])
async def api_my_security_summary(request: Request):
    session = request.session
    username = session.get("username", "")
    rank = "admin" if session.get("is_admin") else _normalize_rank(session.get("rank"))
    caps = _get_caps_for_session(session)

    history = detector.get_scan_history(limit=1000)
    if not session.get("is_admin"):
        history = [row for row in history if row.get("actor") in ("", username)]
    recent = history[:20]
    total = sum(int(r.get("total", 0) or 0) for r in recent)
    phishing = sum(int(r.get("phishing", 0) or 0) for r in recent)

    temp_items = detector.get_temp_trusted_items(limit=400)
    soon = [row for row in temp_items if int(row.get("expires_at", 0)) <= int(time.time() + (24 * 3600))]

    return JSONResponse({
        "username": username,
        "rank": rank,
        "caps": caps,
        "recent_scan_batches": len(recent),
        "recent_links_scanned": total,
        "recent_phishing_hits": phishing,
        "temp_trusted_count": len(temp_items),
        "temp_trusted_expiring_24h": len(soon),
    })

@app.get("/api/temp_trusted", dependencies=[Depends(require_authenticated)])
async def api_temp_trusted(request: Request):
    return JSONResponse({"items": detector.get_temp_trusted_items(limit=400)})

@app.post("/api/temp_trusted", dependencies=[Depends(require_authenticated)])
async def api_add_temp_trusted(request: Request):
    _require_panel_cap(request.session, "whitelist_manage")
    try:
        payload = await request.json()
    except Exception:
        form = await request.form()
        payload = dict(form)

    site = str(payload.get("site", "")).strip()
    if not site:
        return JSONResponse({"error": "site is required"}, status_code=400)
    minutes_raw = payload.get("minutes", TEMP_TRUST_DEFAULT_MINUTES)
    try:
        minutes = int(minutes_raw)
    except Exception:
        minutes = TEMP_TRUST_DEFAULT_MINUTES
    note = str(payload.get("note", "")).strip()
    if len(note) < 4:
        return JSONResponse({"error": "reason/note is required (min 4 chars)"}, status_code=400)
    if minutes < TEMP_TRUST_MIN_MINUTES or minutes > TEMP_TRUST_MAX_MINUTES:
        return JSONResponse({"error": f"minutes must be between {TEMP_TRUST_MIN_MINUTES} and {TEMP_TRUST_MAX_MINUTES}"}, status_code=400)
    ok = await detector.add_temp_user_trusted(
        host=site,
        minutes=minutes,
        added_by=request.session.get("username", "user"),
        note=note,
    )
    await _audit(request, "add_temp_trusted", detector._normalize_host(site), meta={"minutes": minutes, "ok": ok})
    return JSONResponse({"ok": bool(ok)})

@app.post("/api/temp_trusted/remove", dependencies=[Depends(require_authenticated)])
async def api_remove_temp_trusted(request: Request):
    _require_panel_cap(request.session, "whitelist_manage")
    try:
        payload = await request.json()
    except Exception:
        form = await request.form()
        payload = dict(form)
    site = str(payload.get("site", "")).strip()
    if not site:
        return JSONResponse({"error": "site is required"}, status_code=400)
    ok = await detector.remove_temp_user_trusted(site)
    await _audit(request, "remove_temp_trusted", detector._normalize_host(site), meta={"ok": ok})
    return JSONResponse({"ok": bool(ok)})

@app.get("/admin/rank_caps", dependencies=[Depends(require_admin)])
async def admin_rank_caps():
    return JSONResponse({
        "base": RANK_CAPS,
        "overrides": RANK_CAPS_OVERRIDES,
        "effective": _get_rank_caps_matrix(),
    })

@app.post("/admin/rank_caps/update", dependencies=[Depends(require_admin)])
async def admin_rank_caps_update(request: Request):
    global mongo_store
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)

    rank = str(data.get("rank", "")).strip().lower()
    section = str(data.get("section", "")).strip().lower()
    cap_key = str(data.get("cap_key", "")).strip()
    enabled = _parse_bool(data.get("enabled", False))
    try:
        _set_rank_cap_override(rank, section, cap_key, enabled)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if mongo_store:
        await mongo_store.set_rank_caps_overrides(RANK_CAPS_OVERRIDES)
    await _audit(request, "rank_caps_update", target=f"{rank}:{section}:{cap_key}", meta={"enabled": enabled})
    return JSONResponse({"ok": True, "overrides": RANK_CAPS_OVERRIDES, "effective": _get_rank_caps_matrix()})

@app.post("/admin/rank_caps/reset", dependencies=[Depends(require_admin)])
async def admin_rank_caps_reset(request: Request):
    global mongo_store, RANK_CAPS_OVERRIDES
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)
    rank = str(data.get("rank", "")).strip().lower()
    if rank not in RANK_CAPS:
        return JSONResponse({"error": "Invalid rank"}, status_code=400)
    merged = copy.deepcopy(RANK_CAPS_OVERRIDES)
    merged.pop(rank, None)
    RANK_CAPS_OVERRIDES = _sanitize_caps_overrides(merged)
    if mongo_store:
        await mongo_store.set_rank_caps_overrides(RANK_CAPS_OVERRIDES)
    await _audit(request, "rank_caps_reset", target=rank)
    return JSONResponse({"ok": True, "overrides": RANK_CAPS_OVERRIDES, "effective": _get_rank_caps_matrix()})

@app.get("/admin/export_iocs", dependencies=[Depends(require_admin)])
async def admin_export_iocs(include_threat_feed: bool = False, max_items: int = 5000):
    max_items = max(100, min(max_items, 50000))
    rows: List[Dict[str, Any]] = []

    reports = detector.get_reports(limit=max_items)
    aggregate: Dict[str, Dict[str, Any]] = {}
    for row in reports:
        host = detector._normalize_host(str(row.get("domain", "")))
        if not host:
            continue
        item = aggregate.setdefault(host, {"count": 0, "max_probability": 0, "last_seen": row.get("time", "")})
        item["count"] += 1
        item["max_probability"] = max(item["max_probability"], int(row.get("probability", 0) or 0))
        item["last_seen"] = row.get("time", item["last_seen"])

    for host, info in aggregate.items():
        rows.append({
            "type": "reported_suspicious",
            "value": host,
            "confidence": info["max_probability"],
            "count": info["count"],
            "last_seen": info["last_seen"],
            "source": "runtime_reports",
        })

    list_data = detector.get_list_data()
    for host in list_data.get("user_blacklist", []):
        rows.append({
            "type": "manual_blacklist",
            "value": host,
            "confidence": 100,
            "count": 1,
            "last_seen": "",
            "source": "admin_policy",
        })

    for temp in detector.get_temp_trusted_items(limit=2000):
        rows.append({
            "type": "temporary_whitelist",
            "value": temp.get("host", ""),
            "confidence": 0,
            "count": 1,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(temp.get("expires_at", 0)))),
            "source": "temporary_trust",
        })

    if include_threat_feed:
        for host in list(detector.threat_feed)[:max_items]:
            rows.append({
                "type": "threat_feed",
                "value": host,
                "confidence": 99,
                "count": 1,
                "last_seen": "",
                "source": "threat_feed",
            })

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "confidence", "count", "last_seen", "source"])
    for row in rows[:max_items]:
        writer.writerow([
            row.get("type", ""),
            row.get("value", ""),
            row.get("confidence", ""),
            row.get("count", ""),
            row.get("last_seen", ""),
            row.get("source", ""),
        ])
    headers = {"Content-Disposition": "attachment; filename=phishguard_iocs.csv"}
    return HTMLResponse(content=output.getvalue(), headers=headers, media_type="text/csv")

@app.post("/admin/rebuild_feedback_bias", dependencies=[Depends(require_admin)])
async def admin_rebuild_feedback_bias(request: Request, limit: int = 5000):
    global mongo_store
    if not mongo_store:
        return JSONResponse({"error": "Database not configured"}, status_code=500)
    rows = await mongo_store.get_feedback_recent(limit=max(100, min(limit, 20000)))
    detector.feedback_domain_bias = {}
    for row in rows:
        detector._update_feedback_bias_from_feedback(row)
    await mongo_store.set_feedback_domain_bias(detector.feedback_domain_bias)
    await _audit(request, "rebuild_feedback_bias", meta={"rows": len(rows), "domains": len(detector.feedback_domain_bias)})
    return JSONResponse({"ok": True, "rows": len(rows), "domains": len(detector.feedback_domain_bias)})

@app.get("/api/domain_timeline", dependencies=[Depends(require_authenticated)])
async def api_domain_timeline(request: Request, domain: str, hours: int = 168):
    host = detector._normalize_host(domain)
    if not host:
        return JSONResponse({"error": "invalid domain"}, status_code=400)
    points = detector.get_domain_timeline(host, hours=hours, limit=600)
    recent_probs = [int(p.get("probability", 0) or 0) for p in points[-8:]]
    trend = 0
    if len(recent_probs) >= 2:
        trend = recent_probs[-1] - recent_probs[0]
    return JSONResponse({
        "domain": host,
        "points": points,
        "trend_delta": trend,
        "volatility": (max(recent_probs) - min(recent_probs)) if recent_probs else 0,
    })

@app.get("/api/domain_fingerprint", dependencies=[Depends(require_authenticated)])
async def api_domain_fingerprint(request: Request, domain: str):
    host = detector._normalize_host(domain)
    if not host:
        return JSONResponse({"error": "invalid domain"}, status_code=400)
    state = detector.get_fingerprint_state(host)
    if not state:
        return JSONResponse({"domain": host, "found": False})
    return JSONResponse({"domain": host, "found": True, "state": state})

@app.get("/admin/campaigns", dependencies=[Depends(require_admin)])
async def admin_campaigns(hours: int = 72, min_size: int = 2):
    clusters = detector.get_campaign_clusters(hours=hours, min_size=min_size)
    return JSONResponse({"clusters": clusters, "count": len(clusters)})

@app.get("/admin/typosquat_hunt", dependencies=[Depends(require_admin)])
async def admin_typosquat_hunt(brand: str, limit: int = 50):
    brand_host = detector._normalize_host(brand)
    if not brand_host:
        return JSONResponse({"error": "invalid brand domain"}, status_code=400)
    brand_sld = detector._extract_sld(brand_host)
    if not brand_sld:
        return JSONResponse({"error": "invalid brand domain"}, status_code=400)

    candidates: Set[str] = set()
    reports = detector.get_reports(limit=4000)
    for r in reports:
        d = detector._normalize_host(str(r.get("domain", "")))
        if d:
            candidates.add(d)
    candidates.update(list(detector.user_blacklist)[:2000])
    candidates.update(list(detector.threat_feed)[:5000])
    candidates.discard(brand_host)

    scored = []
    for host in candidates:
        sld = detector._extract_sld(host)
        if not sld:
            continue
        sim = detector._similarity(brand_sld, sld)
        dist = _levenshtein_distance(brand_sld, sld)
        contains = brand_sld in sld or sld in brand_sld
        if sim < 72 and dist > 2 and not contains:
            continue
        risk = 0
        if host in detector.threat_feed:
            risk += 35
        if host in detector.user_blacklist:
            risk += 25
        if contains:
            risk += 12
        risk += max(0, sim - 70)
        risk += max(0, 4 - dist) * 3
        scored.append({
            "domain": host,
            "similarity": sim,
            "distance": dist,
            "contains_brand_token": bool(contains),
            "risk": min(100, risk),
            "in_threat_feed": host in detector.threat_feed,
            "in_blacklist": host in detector.user_blacklist,
        })
    scored.sort(key=lambda x: (x["risk"], x["similarity"]), reverse=True)
    return JSONResponse({"brand": brand_host, "items": scored[:max(5, min(limit, 200))]})

@app.post("/admin/incident_playbook", dependencies=[Depends(require_admin)])
async def admin_incident_playbook(request: Request):
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)
    target = str(data.get("domain") or data.get("url") or "").strip()
    host = detector._normalize_host(target)
    if not host:
        return JSONResponse({"error": "domain/url is required"}, status_code=400)

    blocked = await detector.add_user_blacklist(host)
    timeline = detector.get_domain_timeline(host, hours=24 * 14, limit=120)
    fingerprint = detector.get_fingerprint_state(host)
    clusters = detector.get_campaign_clusters(hours=24 * 7, min_size=2)
    related_clusters = [c for c in clusters if host in set(c.get("domains", []))]
    ioc = {
        "type": "incident_block",
        "value": host,
        "confidence": 100,
        "count": len(timeline),
        "last_seen": timeline[-1]["time"] if timeline else "",
        "source": "incident_playbook",
    }
    await _audit(
        request,
        "incident_playbook",
        target=host,
        meta={"blocked": bool(blocked), "timeline_points": len(timeline), "related_clusters": len(related_clusters)},
    )
    return JSONResponse({
        "ok": True,
        "domain": host,
        "blacklist_added": bool(blocked),
        "timeline_points": len(timeline),
        "fingerprint": fingerprint,
        "related_clusters": related_clusters[:5],
        "ioc": ioc,
        "actions": [
            "blacklist_applied",
            "ioc_generated",
            "audit_logged",
        ],
    })

def _weekly_report_payload() -> Dict[str, Any]:
    metrics = detector.get_dashboard_metrics(hours=24 * 7)
    clusters = detector.get_campaign_clusters(hours=24 * 7, min_size=2)
    return {
        "generated_at": _now_str(),
        "window_hours": 24 * 7,
        "metrics": metrics,
        "campaigns": clusters[:15],
    }

@app.get("/admin/weekly_report", dependencies=[Depends(require_admin)])
async def admin_weekly_report():
    return JSONResponse(_weekly_report_payload())

@app.get("/admin/weekly_report.csv", dependencies=[Depends(require_admin)])
async def admin_weekly_report_csv():
    payload = _weekly_report_payload()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["metric", "value"])
    m = payload.get("metrics", {})
    writer.writerow(["generated_at", payload.get("generated_at", "")])
    writer.writerow(["window_hours", payload.get("window_hours", 0)])
    writer.writerow(["reports_count", m.get("reports_count", 0)])
    writer.writerow(["scan_total", m.get("scan_total", 0)])
    writer.writerow(["scan_phishing", m.get("scan_phishing", 0)])
    writer.writerow(["scan_safe", m.get("scan_safe", 0)])
    writer.writerow(["hit_rate_percent", m.get("hit_rate_percent", 0)])
    writer.writerow([])
    writer.writerow(["top_domain", "count"])
    for row in m.get("top_domains", []):
        writer.writerow([row.get("domain", ""), row.get("count", 0)])
    writer.writerow([])
    writer.writerow(["campaign_id", "count", "max_probability", "keyword", "tld", "similar_to"])
    for c in payload.get("campaigns", []):
        writer.writerow([
            c.get("cluster_id", ""),
            c.get("count", 0),
            c.get("max_probability", 0),
            c.get("keyword", ""),
            c.get("tld", ""),
            c.get("similar_to", ""),
        ])
    headers = {"Content-Disposition": "attachment; filename=phishguard_weekly_report.csv"}
    return HTMLResponse(content=output.getvalue(), headers=headers, media_type="text/csv")

@app.post("/admin/honey_tokens", dependencies=[Depends(require_admin)])
async def admin_create_honey_token(request: Request):
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)
    label = str(data.get("label", "training")).strip()[:80]
    row = await detector.create_honey_token(request.session.get("username", "admin"), label=label)
    await _audit(request, "create_honey_token", target=row.get("token", ""), meta={"label": label})
    return JSONResponse({"ok": True, "token": row})

@app.get("/admin/honey_tokens", dependencies=[Depends(require_admin)])
async def admin_honey_tokens():
    return JSONResponse({"tokens": detector.get_honey_tokens_list(), "events": detector.get_honey_events(limit=300)})

@app.get("/api/honey_links", dependencies=[Depends(require_authenticated)])
async def api_honey_links(request: Request):
    tokens = detector.get_honey_tokens_list()
    if not tokens:
        token_row = await detector.create_honey_token(request.session.get("username", "admin"), label="default-training")
        tokens = [token_row]
    base = str(request.base_url).rstrip("/")
    links = [{"token": t.get("token"), "label": t.get("label"), "url": f"{base}/honey/{t.get('token')}"} for t in tokens[:20]]
    return JSONResponse({"links": links})

@app.get("/honey/{token}", response_class=HTMLResponse)
async def honey_page(request: Request, token: str):
    await detector.mark_honey_hit(token, source=request.headers.get("referer", "direct"), ip=_client_ip(request))
    html = f"""
    <!doctype html>
    <html lang='fa' dir='rtl'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>Security Training</title>
    <style>body{{font-family:tahoma;background:#0b1320;color:#eaf2ff;margin:0;padding:24px}}.box{{max-width:700px;margin:0 auto;background:#13203a;border:1px solid #294063;border-radius:12px;padding:20px}}a{{color:#37c0ff}}</style>
    </head><body><div class='box'><h2>تمرین امنیتی</h2><p>این لینک یک Honey-Link آموزشی بود. اگر روی لینک مشکوک کلیک کردید، قبل از ادامه آدرس دامنه را بررسی کنید.</p><p>Token: <code>{token}</code></p><p><a href='/'>بازگشت</a></p></div></body></html>
    """
    return HTMLResponse(content=html)

@app.post("/api/inbox_guardian_scan", dependencies=[Depends(require_authenticated)])
async def api_inbox_guardian_scan(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    urls = data.get("urls", [])
    if not isinstance(urls, list) or not urls:
        return JSONResponse({"error": "urls must be a non-empty list"}, status_code=400)
    urls = [str(u).strip() for u in urls if str(u).strip()]
    urls = urls[:MAX_BATCH_ITEMS]
    team = _normalize_team(request.session.get("team"))
    sem = asyncio.Semaphore(max(2, CHECK_BATCH_CONCURRENCY))

    async def _scan(u: str):
        async with sem:
            res = await detector.check_link(u, lite=True, user_team=team)
        p = int(res.get("probability", 0) or 0)
        if res.get("is_phishing"):
            severity = "critical" if p >= 90 else "high"
            action = "block_and_report"
        elif p >= 45:
            severity = "medium"
            action = "review_before_click"
        else:
            severity = "low"
            action = "allow"
        return {
            "url": u,
            "domain": res.get("domain", ""),
            "probability": p,
            "is_phishing": bool(res.get("is_phishing")),
            "severity": severity,
            "recommended_action": action,
        }

    rows = await asyncio.gather(*[_scan(u) for u in urls], return_exceptions=False)
    rows.sort(key=lambda x: (x["severity"] in ("critical", "high"), x["probability"]), reverse=True)
    await _audit(request, "inbox_guardian_scan", meta={"count": len(rows)})
    return JSONResponse({"count": len(rows), "results": rows})

# Public whitelist endpoints used by the panel and extension.
@app.post("/add_trusted")
async def add_trusted_api(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    try:
        payload = await request.json()
    except Exception:
        form = await request.form()
        payload = dict(form)
    site = str(payload.get("site", "")).strip()
    if not site:
        return JSONResponse({"error": "site is required"}, status_code=400)
    _require_panel_cap(request.session, "whitelist_manage")
    success = await detector.add_user_trusted(site)
    await _audit(request, "add_trusted_api", detector._normalize_host(site), meta={"success": bool(success)})
    return JSONResponse({"ok": bool(success)})
@app.post("/remove_trusted")
async def remove_trusted_api(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    try:
        payload = await request.json()
    except Exception:
        form = await request.form()
        payload = dict(form)
    site = str(payload.get("site", "")).strip()
    if not site:
        return JSONResponse({"error": "site is required"}, status_code=400)
    _require_panel_cap(request.session, "whitelist_manage")
    success = await detector.remove_user_trusted(site)
    await _audit(request, "remove_trusted_api", detector._normalize_host(site), meta={"success": bool(success)})
    return JSONResponse({"ok": bool(success)})
# Client-side report endpoint.
@app.post("/report_phish")
async def report_phish_api(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    url = str(data.get("url", "")).strip()
    if not url:
        return JSONResponse({"error": "url is required"}, status_code=400)

    domain = detector._normalize_host(url)
    probability = int(data.get("probability", 100) or 100)
    similar_to = data.get("similar_to")
    reasons = data.get("reasons")
    if not isinstance(reasons, list):
        reasons = ["Reported by client"]
    detector.add_report(url, domain, probability, similar_to, reasons)
    return JSONResponse({"ok": True})
# Public landing page.
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    context = {"request": request, "extension_download_path": detector.get_extension_path()}
    return templates.TemplateResponse("index.html", context)

# Admin pages and authentication

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):

    # 1. اگر کاربر احراز هویت شده باشد...
    if request.session.get("authenticated"):
        # 2. و اگر ادمین باشد، او را به پنل ادمین هدایت کن.
        if request.session.get("is_admin"):
            return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

        # 3. اگر احراز هویت شده ولی ادمین نیست (کاربر عادی است)،
        # نباید ریدایرکت شود تا بتواند فرم لاگین را ببیند و شاید ادمین شود.

    # 4. در غیر این صورت (ادمین نبودن یا عدم احراز هویت)، فرم لاگین را نمایش بده.
    context = {"request": request, "error": None}
    return templates.TemplateResponse("login.html", context)


@app.post("/login")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    global mongo_store
    try:
        _enforce_rate_limit(request, login_rate_limiter, "login_form")
    except HTTPException:
        context = {"request": request, "error": "تعداد تلاش ورود زیاد است. کمی بعد دوباره تلاش کنید."}
        return templates.TemplateResponse("login.html", context, status_code=429)

    if not mongo_store:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Database not configured."}, status_code=500)

    admin_user_data = await mongo_store.get_admin_user(username)
    if admin_user_data:
        stored_password = admin_user_data.get("password", "")
        if _verify_password(stored_password, password):
            if _password_needs_upgrade(stored_password):
                await mongo_store.update_admin_password(username, password)
            request.session["authenticated"] = True
            request.session["is_admin"] = True
            request.session["username"] = username
            request.session["display_name"] = admin_user_data.get("display_name", username)
            request.session["rank"] = "admin"
            print(f"Admin login successful: {username}")
            await _audit(request, "login_success_admin", username)
            return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)
        else:
            print(f"Admin login failed (wrong password): {username}")
            await _audit(request, "login_failed_admin_password", username)
            context = {"request": request, "error": "نام کاربری یا رمز عبور اشتباه است."}
            return templates.TemplateResponse("login.html", context, status_code=401)

    normal_user_data = await mongo_store.get_normal_user(username)
    if normal_user_data and _verify_password(normal_user_data.get("password", ""), password):
        if _password_needs_upgrade(normal_user_data.get("password", "")):
            await mongo_store.update_normal_user_password(username, password)
        request.session["authenticated"] = True
        request.session["is_admin"] = False
        request.session["username"] = username
        request.session["display_name"] = normal_user_data.get("display_name", username)
        request.session["rank"] = _normalize_rank(normal_user_data.get("rank"))
        request.session["team"] = _normalize_team(normal_user_data.get("team"))
        await _audit(request, "login_success_user", username)
        return RedirectResponse(url=app.url_path_for("user_panel"), status_code=status.HTTP_302_FOUND)

    print(f"Login failed for user: {username}")
    await _audit(request, "login_failed", username)
    context = {"request": request, "error": "نام کاربری یا رمز عبور اشتباه است."}
    return templates.TemplateResponse("login.html", context, status_code=401)


# API login used by the browser extension.
@app.post("/api/extension_login")
async def api_extension_login(request: Request):
    global mongo_store
    _enforce_rate_limit(request, login_rate_limiter, "extension_login")
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
    except Exception:
        return JSONResponse({"success": False, "error": "Invalid request"}, status_code=400)

    if not mongo_store:
        return JSONResponse({"success": False, "error": "Database not configured"}, status_code=500)

    user_data = await mongo_store.get_normal_user(username)
    if user_data and _verify_password(user_data.get("password", ""), password):
        if _password_needs_upgrade(user_data.get("password", "")):
            await mongo_store.update_normal_user_password(username, password)
        rank = _normalize_rank(user_data.get("rank"))
        team = _normalize_team(user_data.get("team"))
        caps = _resolve_rank_caps(rank, is_admin=False)
        await mongo_store.add_audit_log(
            actor=f"extension:{username}",
            action="extension_login_success_user",
            target=username or "",
            ip=_client_ip(request),
        )
        return JSONResponse({
            "success": True,
            "displayName": user_data.get("display_name", username),
            "rank": rank,
            "team": team,
            "isAdmin": False,
            "capabilities": caps,
        })

    admin_data = await mongo_store.get_admin_user(username)
    if admin_data and _verify_password(admin_data.get("password", ""), password):
        if _password_needs_upgrade(admin_data.get("password", "")):
            await mongo_store.update_admin_password(username, password)
        await mongo_store.add_audit_log(
            actor=f"extension:{username}",
            action="extension_login_success_admin",
            target=username or "",
            ip=_client_ip(request),
        )
        return JSONResponse({
            "success": True,
            "displayName": admin_data.get("display_name", username) + " (Admin)",
            "rank": "admin",
            "team": "admin",
            "isAdmin": True,
            "capabilities": _resolve_rank_caps("admin", is_admin=True),
        })

    await mongo_store.add_audit_log(
        actor=f"extension:{username or 'unknown'}",
        action="extension_login_failed",
        target=username or "",
        ip=_client_ip(request),
    )
    return JSONResponse({"success": False, "error": "Username or password is incorrect."}, status_code=401)


@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("username", "Unknown")
    await _audit(request, "logout", username)
    request.session.clear()
    print(f"User logout: {username}")
    return RedirectResponse(url=app.url_path_for("index"), status_code=status.HTTP_302_FOUND)

# Admin page context.
@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request, admin_username: str = Depends(require_admin)):
    list_data = detector.get_list_data()
    reports = detector.get_reports()
    metrics = detector.get_dashboard_metrics(hours=24)
    global mongo_store

    if not mongo_store:
        raise HTTPException(status_code=500, detail="Database not configured.")

    all_admin_users = await mongo_store.get_all_admin_users()
    all_normal_users = await mongo_store.get_all_normal_users()

    context = {
        "request": request,
        "trusted_count": list_data["global_count"],
        "user_trusted": list_data["user_trusted"],
        "user_blacklist": list_data["user_blacklist"],
        "temp_user_trusted": list_data.get("temp_user_trusted", []),
        "recent": reports,
        "metrics": metrics,
        "server_sensitivity": detector.server_sensitivity,
        "current_extension_file": detector.extension_filename,
        "server_health": detector.get_health_status(),
        "admin_display_name": request.session.get("display_name", admin_username),
        "all_admin_users": all_admin_users,
        "all_normal_users": all_normal_users,
        "rank_caps_matrix": _get_rank_caps_matrix(),
        "rank_caps_overrides": RANK_CAPS_OVERRIDES,
        "teams": TEAMS,
        "team_policy": TEAM_SENSITIVITY_OFFSET,
    }
    return templates.TemplateResponse("admin.html", context)

# User panel page.
@app.get("/userpanel", response_class=HTMLResponse)
async def user_panel(request: Request, session: dict = Depends(require_authenticated)):
    list_data = detector.get_list_data()
    reports = detector.get_reports()
    metrics = detector.get_dashboard_metrics(hours=24)
    caps = _get_caps_for_session(session)
    rank = "admin" if session.get("is_admin") else _normalize_rank(session.get("rank"))

    context = {
        "request": request,
        "trusted_count": list_data["global_count"],
        "user_trusted": list_data["user_trusted"],
        "user_blacklist": list_data["user_blacklist"],
        "temp_user_trusted": list_data.get("temp_user_trusted", []),
        "recent": reports,
        "metrics": metrics,
        "server_sensitivity": detector.server_sensitivity,
        "server_health": detector.get_health_status(),
        "admin_display_name": session.get("display_name", session.get("username")),
        "caps": caps,
        "user_rank": rank,
        "user_team": _normalize_team(session.get("team")),
        "team_policy": TEAM_SENSITIVITY_OFFSET,
        # Keep system-level admin data out of the normal user panel.
    }
    # Render the separate user panel template.
    return templates.TemplateResponse("userpanel.html", context)


# Admin and panel POST endpoints.

@app.post("/admin/upload_extension", dependencies=[Depends(require_admin)])
async def admin_upload_extension(request: Request, extension_file: UploadFile = File(...)):
    if not extension_file.filename or not extension_file.filename.endswith(('.zip', '.crx')):
        print("Upload failed: Invalid file type or no filename.")
        return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

    safe_filename = f"{int(time.time())}_{os.path.basename(extension_file.filename)}"
    file_path = os.path.join(detector.EXTENSION_UPLOAD_DIR, safe_filename)
    try:
        contents = await extension_file.read()
        def _save_file_and_cleanup():
            with open(file_path, "wb") as buffer: buffer.write(contents)
            detector._cleanup_old_extension_files(safe_filename)
        await asyncio.to_thread(_save_file_and_cleanup)
        await detector.set_extension_filename(safe_filename)
        print(f"Extension file uploaded: {safe_filename}")
        await _audit(request, "upload_extension", safe_filename, meta={"bytes": len(contents)})
    except Exception as e: print(f"File upload failed: {e}")
    return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)


# These actions are shared by admin and user panels; rank capabilities decide what each user can do.

@app.post("/admin/add_trusted", dependencies=[Depends(require_authenticated)])
async def admin_add_trusted_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "whitelist_manage")
    success = await detector.add_user_trusted(site)
    await _audit(request, "add_trusted", detector._normalize_host(site), meta={"success": bool(success)})
    print(f"User {request.session.get('username')} added trusted: {site} (Success: {success})")
    # Send the user back to the panel they came from.
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_trusted", dependencies=[Depends(require_authenticated)])
async def admin_remove_trusted_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "whitelist_manage")
    success = await detector.remove_user_trusted(site)
    await _audit(request, "remove_trusted", detector._normalize_host(site), meta={"success": bool(success)})
    print(f"User {request.session.get('username')} removed trusted: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

# Blacklist endpoints are available only to users whose rank allows blacklist management.
@app.post("/admin/add_blacklist", dependencies=[Depends(require_authenticated)])
async def admin_add_blacklist_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "blacklist_manage")
    success = await detector.add_user_blacklist(site)
    await _audit(request, "add_blacklist", detector._normalize_host(site), meta={"success": bool(success)})
    print(f"User {request.session.get('username')} added blacklist: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

@app.post("/admin/add_blacklist_suffix", dependencies=[Depends(require_authenticated)])
async def admin_add_blacklist_suffix_form(request: Request, suffix: str = Form(...)):
    _require_panel_cap(request.session, "blacklist_manage")
    cleaned = str(suffix or "").strip().lower()
    if cleaned and not cleaned.startswith("*.") and not cleaned.startswith("."):
        cleaned = f"*.{cleaned.lstrip('.')}"
    success = await detector.add_user_blacklist(cleaned) if cleaned else False
    await _audit(request, "add_blacklist_suffix", cleaned, meta={"success": bool(success)})
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_blacklist", dependencies=[Depends(require_authenticated)])
async def admin_remove_blacklist_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "blacklist_manage")
    success = await detector.remove_user_blacklist(site)
    await _audit(request, "remove_blacklist", detector._normalize_host(site), meta={"success": bool(success)})
    print(f"User {request.session.get('username')} removed blacklist: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

# Sensitivity and manual analysis are admin-only.

@app.post("/admin/set_sensitivity", dependencies=[Depends(require_admin)])
async def admin_set_sensitivity(request: Request, sensitivity: int = Form(...)):
    await detector.set_server_sensitivity(sensitivity)
    await _audit(request, "set_sensitivity", meta={"value": int(sensitivity)})
    return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

# Manual analysis endpoint for admins.
@app.post("/admin/analyze_url", dependencies=[Depends(require_admin)])
async def admin_analyze_url(request: Request):
    try: data = await request.json(); url = data.get("url")
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not url: return JSONResponse({"error": "URL not provided"}, status_code=400)
    try:
        # Admin analysis uses the server-wide sensitivity policy.
        result = await detector.check_link(url)
        await _audit(request, "admin_analyze_url", detector._normalize_host(url), meta={"probability": result.get("probability", 0)})
        return JSONResponse(result)
    except HTTPException as he: return JSONResponse(he.detail, status_code=he.status_code)
    except Exception as e: return JSONResponse({"is_phishing": False, "error": f"Analysis error: {e}"}, status_code=500)

# Backup endpoints for admins.
@app.get("/admin/backup_whitelist", dependencies=[Depends(require_admin)])
async def admin_backup_whitelist():
    if not mongo_store:
        return JSONResponse({"error": "Database not configured"}, status_code=500)
    trusted = await mongo_store.get_list("user_trusted")
    return JSONResponse(content=trusted, headers={"Content-Disposition": "attachment; filename=user_trusted_backup.json"})

@app.get("/admin/backup_logs", dependencies=[Depends(require_admin)])
async def admin_backup_logs():
    reports = await asyncio.to_thread(detector.get_reports, limit=10000)
    return JSONResponse(content=reports, headers={"Content-Disposition": "attachment; filename=phishguard_logs_backup.json"})

# Purge reports endpoint for admins.
@app.post("/admin/purge_logs", dependencies=[Depends(require_admin)])
async def admin_purge_logs():
    try:
        await asyncio.to_thread(detector.purge_reports)
        return JSONResponse({"status": "success"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)

# Admin user management endpoints.
@app.post("/admin/add_user", dependencies=[Depends(require_admin)])
async def admin_add_user(request: Request,
                         new_username: str = Form(...),
                         new_password: str = Form(...),
                         display_name: str = Form(...)):
    if not new_username or not new_password or not display_name:
        # Missing fields are ignored and the admin stays on the user-management tab.
        return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

    added = await mongo_store.add_admin_user(new_username, new_password, display_name)
    if not added:
        print(f"Add admin user failed: {new_username} already exists.")
    else:
        print(f"Admin user added: {new_username}")
    await _audit(request, "add_admin_user", new_username, meta={"success": bool(added)})
    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_user", dependencies=[Depends(require_admin)])
async def admin_remove_user(request: Request, username_to_remove: str = Form(...)):
    current_user = request.session.get("username")

    if username_to_remove == current_user:
        # Never let an admin remove their own active account.
        print("Remove admin user failed: Cannot remove self.")
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)
    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)
    if await mongo_store.admin_count() <= 1:
        # Keep at least one admin account available.
        print("Remove admin user failed: Cannot remove the last admin.")
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    removed = await mongo_store.remove_admin_user(username_to_remove)
    if removed:
        print(f"Admin user removed: {username_to_remove}")
    else:
        print(f"Remove admin user failed: {username_to_remove} not found.")
    await _audit(request, "remove_admin_user", username_to_remove, meta={"success": bool(removed)})

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)


# Normal user management endpoints.
@app.post("/admin/add_normal_user", dependencies=[Depends(require_admin)])
async def admin_add_normal_user(request: Request,
                                new_normal_username: str = Form(...),
                                new_normal_password: str = Form(...),
                                normal_display_name: str = Form(...),
                                normal_rank: str = Form(DEFAULT_RANK),
                                normal_team: str = Form(DEFAULT_TEAM)):
    if not new_normal_username or not new_normal_password or not normal_display_name:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    added = await mongo_store.add_normal_user(
        new_normal_username,
        new_normal_password,
        normal_display_name,
        normal_rank,
        normal_team,
    )
    if not added:
        print(f"Add normal user failed: {new_normal_username} already exists.")
    else:
        print(f"Normal user added: {new_normal_username}")
    await _audit(
        request,
        "add_normal_user",
        new_normal_username,
        meta={"success": bool(added), "rank": _normalize_rank(normal_rank), "team": _normalize_team(normal_team)},
    )
    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_normal_user", dependencies=[Depends(require_admin)])
async def admin_remove_normal_user(request: Request, username_to_remove_normal: str = Form(...)):
    # Normal users are separate from admin accounts, so there is no self-removal edge case here.
    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    removed = await mongo_store.remove_normal_user(username_to_remove_normal)
    if removed:
        print(f"Normal user removed: {username_to_remove_normal}")
    else:
        print(f"Remove normal user failed: {username_to_remove_normal} not found.")
    await _audit(request, "remove_normal_user", username_to_remove_normal, meta={"success": bool(removed)})

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/update_normal_user_rank", dependencies=[Depends(require_admin)])
async def admin_update_normal_user_rank(
    request: Request,
    username_to_update: str = Form(...),
    normal_rank: str = Form(DEFAULT_RANK),
):
    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    updated = await mongo_store.update_normal_user_rank(username_to_update, normal_rank)
    if updated:
        print(f"Normal user rank updated: {username_to_update} -> {_normalize_rank(normal_rank)}")
    else:
        print(f"Update rank failed: {username_to_update} not found.")
    await _audit(request, "update_normal_user_rank", username_to_update, meta={"success": bool(updated), "rank": _normalize_rank(normal_rank)})

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/update_normal_user_team", dependencies=[Depends(require_admin)])
async def admin_update_normal_user_team(
    request: Request,
    username_to_update: str = Form(...),
    normal_team: str = Form(DEFAULT_TEAM),
):
    if not mongo_store:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    updated = await mongo_store.update_normal_user_team(username_to_update, normal_team)
    await _audit(
        request,
        "update_normal_user_team",
        username_to_update,
        meta={"success": bool(updated), "team": _normalize_team(normal_team)},
    )
    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)


# Controlled shutdown endpoint for admins.
@app.post("/admin/shutdown", dependencies=[Depends(require_admin)])
async def admin_shutdown():
    print("--- 🛑 Server Shutdown Request Received (Admin) 🛑 ---")
    def shutdown_server(): time.sleep(0.5); os._exit(0)
    threading.Thread(target=shutdown_server).start()
    return JSONResponse({"status": "Server shutting down!"})

if __name__ == "__main__":
    # Create the trusted-domain cache file on first boot.
    if not os.path.exists(TRUSTED_GLOBAL_CACHE):
        print(f"Creating empty file: {TRUSTED_GLOBAL_CACHE}")
        with open(TRUSTED_GLOBAL_CACHE, 'w') as fp:
            json.dump([], fp)

    host = os.environ.get("PHISH_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    print(f"Server starting on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
