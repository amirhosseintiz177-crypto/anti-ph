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
from typing import List, Dict, Any, Set, Optional
from fastapi import FastAPI, HTTPException, Request, Form, Depends, status, UploadFile, File
# --- NEW --- Import FileResponse for backups
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
import numpy as np
# --- NEW --- Import password hashing library (important for real use!)
# For , we won't implement hashing now, but you SHOULD use it.
# import hashlib # Example using built-in hashlib

# Fuzzy
try:
    from rapidfuzz import fuzz
    FUZZY_LIB = 'rapidfuzz'
    print("Using rapidfuzz (WRatio) for optimized fuzzy matching.")
except ImportError:
    from difflib import SequenceMatcher
    def ratio_fallback(a, b):
        return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100
    fuzz = type('FuzzModule', (object,), {'ratio': ratio_fallback})
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

# --- Setup ---

TRUSTED_GLOBAL_CACHE = "trusted_global.json"

DATA_DIR = os.environ.get("PHISH_DATA_DIR", "").strip()
def data_file(filename: str) -> str:
    if not DATA_DIR:
        return filename
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        return os.path.join(DATA_DIR, filename)
    except OSError:
        return filename

USER_TRUSTED_FILE = data_file("user_trusted.json")
# --- NEW --- Blacklist file
USER_BLACKLIST_FILE = data_file("user_blacklist.json")
# --- NEW --- Admin users file
ADMIN_USERS_FILE = data_file("admin_users.json")
# --- NEW --- Normal users file
NORMAL_USERS_FILE = data_file("normal_users.json")


SECRET_KEY = os.environ.get("PHISH_SECRET_KEY", "your-default-very-secret-key-please-change-it")
# --- REMOVED --- Single admin user/pass from env vars - now managed in file
# ADMIN_USER = os.environ.get("PHISH_ADMIN_USER", "admin")
# ADMIN_PASS = os.environ.get("PHISH_ADMIN_PASS", "12345")
SERVER_SENSITIVITY_FILE = data_file("server_sensitivity.json")

RANKS = ["basic", "plus", "pro"]
DEFAULT_RANK = "basic"
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

def _normalize_rank(rank: Optional[str]) -> str:
    if not rank:
        return DEFAULT_RANK
    rank = rank.strip().lower()
    return rank if rank in RANK_CAPS else DEFAULT_RANK

def _get_caps_for_session(session: dict) -> Dict[str, Any]:
    if session.get("is_admin"):
        return RANK_CAPS["admin"]
    return RANK_CAPS[_normalize_rank(session.get("rank"))]

def _require_panel_cap(session: dict, cap_key: str):
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get(cap_key, False):
        raise HTTPException(status_code=403, detail="Insufficient rank for this action.")

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
    if "trusted by user" in text.lower():
        return "Trusted (user)"
    if "trusted globally" in text.lower():
        return "Trusted (global)"
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
    if "long url" in text.lower():
        return "Long URL"
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
    return reasons[0]

async def _redirect_chain(url: str, max_hops: int = 8) -> List[str]:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
            chain = [str(r.url) for r in resp.history] + [str(resp.url)]
            return chain[:max_hops]
    except Exception:
        return []

app = FastAPI(title="Local Phishing Detector API")

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


templates = Jinja2Templates(directory="templates")

# --- NEW --- Helper functions for user databases ---
def _load_user_db(file_path: str, default_user: str, default_pass: str, default_name: str, default_profile: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, str]]:
    """Loads a user database from a JSON file."""
    if not os.path.exists(file_path):
        # Create default admin if file doesn't exist
        # IMPORTANT: In production, hash the password!
        # hashed_pass = hashlib.sha256(default_pass.encode()).hexdigest()
        profile = default_profile.copy() if default_profile else {}
        default_users = {
            default_user: {"password": default_pass, "display_name": default_name, **profile}
        }
        _save_user_db(file_path, default_users)
        return default_users
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading user file {file_path}: {e}. Using default.")
        profile = default_profile.copy() if default_profile else {}
        return {default_user: {"password": default_pass, "display_name": default_name, **profile}}

def _save_user_db(file_path: str, users: Dict[str, Dict[str, str]]):
    """Saves a user database to a JSON file."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Error saving user file {file_path}: {e}")

# Load admin users at startup
admin_users_db = _load_user_db(ADMIN_USERS_FILE, "admin", "12345", "Default Admin")
admin_users_lock = threading.Lock() # Lock for modifying admin users

# --- NEW --- Load normal users at startup
normal_users_db = _load_user_db(
    NORMAL_USERS_FILE,
    "user",
    "123",
    "Normal User",
    default_profile={"rank": DEFAULT_RANK},
)
normal_users_lock = threading.Lock() # Lock for modifying normal users

def _ensure_normal_user_ranks():
    global normal_users_db
    updated = False
    for username, data in normal_users_db.items():
        if not isinstance(data, dict):
            normal_users_db[username] = {"password": "", "display_name": username, "rank": DEFAULT_RANK}
            updated = True
            continue
        normalized_rank = _normalize_rank(data.get("rank"))
        if data.get("rank") != normalized_rank:
            data["rank"] = normalized_rank
            updated = True
    if updated:
        _save_user_db(NORMAL_USERS_FILE, normal_users_db)

_ensure_normal_user_ranks()


# --- MLPhishingModel Class (Unchanged) ---
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
            self.is_healthy = True # Allow fallback simulation
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

# --- PhishDetector Class (MODIFIED) ---
class PhishDetector:

    TRUSTED_CACHE = TRUSTED_GLOBAL_CACHE
    USER_TRUSTED_FILE = USER_TRUSTED_FILE
    # --- NEW --- Blacklist file constant
    USER_BLACKLIST_FILE = USER_BLACKLIST_FILE
    REPO_RAW_URL = "https://s27.uupload.ir/files/09171258914/cloudflare-radar_top-1000000-domains_20251103-20251110.csv" # Or your preferred source
    EXTENSION_FILE_INFO = "extension_file_info.json"
    EXTENSION_UPLOAD_DIR = "static/extension_files"

    def __init__(self):
        # Synchronization Primitives
        self.list_lock = threading.RLock() # --- MODIFIED --- Use RLock for trusted/blacklist
        self.reports_lock = threading.Lock()
        self.sensitivity_lock = threading.RLock() # Keep RLock for sensitivity
        self.health_lock = threading.Lock()

        # Data Stores
        self.trusted_global: Set[str] = set()
        self.user_trusted: Set[str] = set()
        # --- NEW --- Blacklist store
        self.user_blacklist: Set[str] = set()
        self.reports: List[Dict[str, Any]] = []
        self.scan_history_lock = threading.Lock()
        self.scan_history: List[Dict[str, Any]] = []
        self.server_sensitivity = self._load_sensitivity(default=90) # Default sensitivity 90

        self.extension_filename: Optional[str] = None
        os.makedirs(self.EXTENSION_UPLOAD_DIR, exist_ok=True)

        self.ml_model = MLPhishingModel()

        self.health_status = {"ml_model": "OK" if self.ml_model.is_healthy else "FAILED",
                              "global_cache": "CHECKING",
                              "last_ping": time.time()}

        self._load_data_on_startup()
        print(f"PhishDetector initialized. Sensitivity: {self.server_sensitivity}%")

    # --- Utility Methods (mostly unchanged, added blacklist save/load) ---
    def _normalize_host(self, u: str) -> str:
        s = (u or "").strip().lower()
        if "://" in s: s = urllib.parse.urlparse(s).netloc
        s = s.split("/", 1)[0].split(":")[0]
        return s.replace("www.", "")

    def _similarity(self, a: str, b: str) -> int:
        if not a or not b: return 0
        if FUZZY_LIB == 'rapidfuzz': return int(fuzz.WRatio(a.lower(), b.lower()))
        else: return int(fuzz.ratio(a.lower(), b.lower()))

    # --- MODIFIED --- Generic save/load using the list_lock
    def _save_json_set(self, path: str, data: Set[str]):
        with self.list_lock: # Protect file writing
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(sorted(list(data)), f, ensure_ascii=False, indent=2)
            except Exception as e: print(f"[_save_json_set] error saving {path}: {e}")

    def _load_json_set(self, path: str) -> Set[str]:
        # No lock needed for initial load, but maybe for refresh? Let's keep it simple.
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    # Normalize during load
                    return set(self._normalize_host(d) for d in json.load(f) if self._normalize_host(d))
        except Exception as e: print(f"[_load_json_set] error loading {path}: {e}"); return set()
        return set()

    def _load_sensitivity(self, default: int) -> int:
        try:
            if os.path.exists(SERVER_SENSITIVITY_FILE):
                with open(SERVER_SENSITIVITY_FILE, 'r') as f: return int(json.load(f).get("sensitivity", default))
        except Exception: pass
        return default

    def _save_sensitivity(self):
        # Assumes sensitivity_lock is held by caller (set_server_sensitivity)
        try:
            with open(SERVER_SENSITIVITY_FILE, 'w') as f: json.dump({"sensitivity": self.server_sensitivity}, f)
        except Exception as e: print(f"Error saving sensitivity: {e}")

    def _load_extension_file_info(self) -> Optional[str]:
        try:
            if os.path.exists(self.EXTENSION_FILE_INFO):
                with open(self.EXTENSION_FILE_INFO, 'r') as f: return json.load(f).get("filename")
        except Exception: return None
        return None

    def _save_extension_file_info(self, filename: str):
        self.extension_filename = filename
        try:
            with open(self.EXTENSION_FILE_INFO, 'w') as f: json.dump({"filename": filename}, f)
        except Exception as e: print(f"Error saving extension filename: {e}")

    def _cleanup_old_extension_files(self, current_filename: str):
        try:
            for filename in os.listdir(self.EXTENSION_UPLOAD_DIR):
                if filename != current_filename:
                    file_path = os.path.join(self.EXTENSION_UPLOAD_DIR, filename)
                    if os.path.isfile(file_path): os.remove(file_path); print(f"Cleaned up: {filename}")
        except Exception as e: print(f"Error during file cleanup: {e}")

    def get_extension_path(self) -> Optional[str]:
        if self.extension_filename: return f"/static/extension_files/{self.extension_filename}"
        return None

    # --- Data Loading (MODIFIED) ---
    def _load_data_on_startup(self):
        self.user_trusted = self._load_json_set(self.USER_TRUSTED_FILE)
        # --- NEW --- Load blacklist
        self.user_blacklist = self._load_json_set(self.USER_BLACKLIST_FILE)
        self.trusted_global = self._load_json_set(self.TRUSTED_CACHE)
        self.extension_filename = self._load_extension_file_info()
        print(f"Loaded {len(self.trusted_global)} global, {len(self.user_trusted)} trusted, {len(self.user_blacklist)} blacklisted domains.")

    async def _refresh_trusted_global(self):
        print(f"Refreshing global trusted list from {self.REPO_RAW_URL} (Async)...")
        try:
            async with httpx.AsyncClient(timeout=45) as client: response = await client.get(self.REPO_RAW_URL)
            response.raise_for_status()
            lines = response.text.splitlines()
            if lines and ('rank' in lines[0].lower() or 'domain' in lines[0].lower()): lines = lines[1:]

            def _process_lines(lines):
                temp_set = set()
                for line in lines:
                    parts = line.split(',', 1); domain_part = parts[1] if len(parts) == 2 else parts[0]
                    normalized = self._normalize_host(domain_part)
                    if normalized and '.' in normalized: temp_set.add(normalized)
                return temp_set

            new_set = await asyncio.to_thread(_process_lines, lines)
            if new_set:
                def _save_and_update(new_set):
                     # --- MODIFIED --- Use the generic save function
                    self.trusted_global = new_set
                    self._save_json_set(self.TRUSTED_CACHE, self.trusted_global)

                await asyncio.to_thread(_save_and_update, new_set)
                with self.health_lock: self.health_status["global_cache"] = f"OK ({len(new_set)})"
                print(f"Refreshed global list: {len(self.trusted_global)} domains.")
        except Exception as e:
            with self.health_lock: self.health_status["global_cache"] = f"FAILED: {e.__class__.__name__}"
            print(f"Error refreshing global list: {e}")

    async def _trusted_refresher_worker(self):
        if not self.trusted_global or len(self.trusted_global) < 100: await self._refresh_trusted_global()
        while True: await asyncio.sleep(6 * 60 * 60); await self._refresh_trusted_global() # Refresh every 6 hours

    # --- Public Data Methods (MODIFIED, added blacklist methods) ---
    def add_user_trusted(self, host: str) -> bool:
        host = self._normalize_host(host);
        if not host: return False
        with self.list_lock:
            if host not in self.user_trusted:
                self.user_trusted.add(host)
                self._save_json_set(self.USER_TRUSTED_FILE, self.user_trusted)
                return True
        return False

    def remove_user_trusted(self, host: str) -> bool:
        host = self._normalize_host(host);
        if not host: return False
        with self.list_lock:
            if host in self.user_trusted:
                self.user_trusted.remove(host)
                self._save_json_set(self.USER_TRUSTED_FILE, self.user_trusted)
                return True
        return False

    # --- NEW --- Blacklist add method
    def add_user_blacklist(self, host: str) -> bool:
        host = self._normalize_host(host);
        if not host: return False
        with self.list_lock:
            if host not in self.user_blacklist:
                self.user_blacklist.add(host)
                self._save_json_set(self.USER_BLACKLIST_FILE, self.user_blacklist)
                return True
        return False

    # --- NEW --- Blacklist remove method
    def remove_user_blacklist(self, host: str) -> bool:
        host = self._normalize_host(host);
        if not host: return False
        with self.list_lock:
            if host in self.user_blacklist:
                self.user_blacklist.remove(host)
                self._save_json_set(self.USER_BLACKLIST_FILE, self.user_blacklist)
                return True
        return False

    # --- MODIFIED --- Get data includes blacklist
    def get_list_data(self):
        with self.list_lock:
            return {
                "global_count": len(self.trusted_global),
                "user_trusted": sorted(list(self.user_trusted)),
                "user_blacklist": sorted(list(self.user_blacklist))
            }

    def get_reports(self, limit: int = 250) -> List[Dict[str, Any]]:
        with self.reports_lock: return self.reports[:limit]

    def add_report(self, url: str, domain: str, probability: int, similar_to: Optional[str], reasons: List[str]):
        report = {"url": url, "domain": domain, "probability": probability, "similar_to": similar_to, "reasons": reasons, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        with self.reports_lock: self.reports.insert(0, report); self.reports = self.reports[:1000] # Keep max 1000 reports

    def add_scan_history(self, entry: Dict[str, Any]):
        with self.scan_history_lock:
            self.scan_history.insert(0, entry)
            self.scan_history = self.scan_history[:500]

    def get_scan_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.scan_history_lock:
            return self.scan_history[:limit]

    # --- NEW --- Method to clear reports
    def purge_reports(self):
        with self.reports_lock:
            self.reports = []
            print("All reports purged by admin.")

    def set_server_sensitivity(self, sensitivity: int):
        with self.sensitivity_lock:
            self.server_sensitivity = max(50, min(100, sensitivity))
            self._save_sensitivity() # Save immediately

    def get_health_status(self) -> Dict[str, Any]:
        with self.health_lock:
            self.health_status["uptime_seconds"] = int(time.time() - self.health_status.get("last_ping", time.time()))
            self.health_status["ml_model"] = "OK" if self.ml_model.is_healthy else "FAILED"
            return self.health_status.copy()

    # ######################################
    # ### BEGINNING OF FULL CODE FIX ###
    # ######################################
    
    # --- Main Detector Logic (MODIFIED FOR PRECISION) ---
    async def check_link(self, target_url: str, user_sensitivity: Optional[int] = None) -> Dict[str, Any]:
        target_host = self._normalize_host(target_url)
        if not target_host: return {"is_phishing": False, "domain": "", "probability": 0, "reasons": ["Invalid host"]}

        # --- Check Blacklist FIRST ---
        with self.list_lock: # Need lock to read blacklist safely
            if target_host in self.user_blacklist:
                self.add_report(target_url, target_host, 100, "N/A", ["Force blocked by blacklist"])
                return {"is_phishing": True, "domain": target_host, "probability": 100, "reasons": ["Force blocked by blacklist"], "similar_to": None}

        # *****************************************************************
        # --- Trusted/Clean Check: IMMEDIATE EXIT ON EXACT MATCH (Optimized) ---
        # این بخش، که خواسته شماست، تضمین می‌کند در صورت تطابق دقیق، تحلیل فازی متوقف شود.
        # *****************************************************************
        with self.list_lock:
            if target_host in self.user_trusted: 
                return {"is_phishing": False, "domain": target_host, "probability": 0, "reasons": ["Trusted by user"]}
            if target_host in self.trusted_global: 
                return {"is_phishing": False, "domain": target_host, "probability": 0, "reasons": ["Trusted globally"]}
        # *****************************************************************

        indicators = _url_indicators(target_url, target_host)

        # ML Model Health Check
        if not self.ml_model.is_healthy:
            raise HTTPException(status_code=503, detail={"error": "ML Model unavailable", "message": "DL model failed."})

        # --- Determine sensitivity and threshold ---
        effective_sensitivity = user_sensitivity if user_sensitivity is not None else self.server_sensitivity
        # High sensitivity = lower threshold (e.g., 90 sens -> 55 threshold)
        # Low sensitivity = high threshold (e.g., 50 sens -> 75 threshold)
        PHISH_THRESHOLD = int(round(max(50, min(95, 100 - (effective_sensitivity * 0.5)))))

        # Offload blocking work
        try:
            # --- Pass sensitivity and threshold into the thread ---
            def _blocking_check(sensitivity_level: int, threshold_level: int):
                target_host_len = len(target_host); max_similarity = 0; most_similar_trusted: Optional[str] = None
                
                with self.list_lock:
                    combined_trusted = self.trusted_global.union(self.user_trusted)

                # --- Find best match (FUZZY MATCHING STARTS HERE) ---
                for trusted_host in combined_trusted:
                    trusted_host_len = len(trusted_host)
                    if abs(trusted_host_len - target_host_len) > 8: continue # Length optimization
                    sim = self._similarity(target_host, trusted_host)
                    if sim < 60: continue # Minimum similarity gate
                    if sim > max_similarity: max_similarity = sim; most_similar_trusted = trusted_host

                # --- Decision Logic ---
                is_phishing = False; probability = 0; reasons = []
                if max_similarity >= 60 and most_similar_trusted:
                    ml_risk_score = self.ml_model.predict_risk(target_host, most_similar_trusted, max_similarity)

                    # ###############
                    # ### PRECISION FIX (Gap-Fill Probability Logic) ###
                    # ###############
                    
                    # 1. Create a sensitivity multiplier between 0.5 (for 50 sens)
                    #    and 1.5 (for 100 sens). The midpoint (75 sens) is 1.0.
                    sensitivity_multiplier = 0.5 + (sensitivity_level - 50) * 0.02
                    
                    # 2. Adjust the ML risk score (0.0 to 1.0) by the sensitivity.
                    #    This determines *how much* of the remaining gap to fill.
                    adjusted_risk_score = min(1.0, ml_risk_score * sensitivity_multiplier)

                    # 3. Calculate how much to add to the base similarity score.
                    remaining_gap = 100 - max_similarity
                    boost_to_add = remaining_gap * adjusted_risk_score
                    
                    # 4. Final probability is the base match + the calculated boost.
                    probability = int(round(max_similarity + boost_to_add))
                    
                    # ###############
                    # ###  END FIX  ###
                    # ###############
                    
                    reasons.append(f"Fuzzy Match: {max_similarity}% (to {most_similar_trusted})")
                    reasons.append(f"ML Risk Score: {ml_risk_score:.2f} (Gap-Fill Boost: +{boost_to_add:.1f}%)")
                    
                    if probability >= threshold_level:
                        is_phishing = True; reasons.append(f"Final ({probability}%) >= Threshold ({threshold_level}%)")
                    else:
                         reasons.append(f"Final ({probability}%) < Threshold ({threshold_level}%)") # Safe reason
                else:
                    reasons.append("No trusted domain similar enough (>60%) found.")

                return is_phishing, probability, most_similar_trusted, reasons

            # --- Pass the calculated values to the thread ---
            is_phishing, probability, most_similar_trusted, reasons = await asyncio.to_thread(
                _blocking_check, effective_sensitivity, PHISH_THRESHOLD
            )

            if indicators:
                reasons.extend([f"Indicator: {i}" for i in indicators])

            # Report only if phishing
            if is_phishing:
                self.add_report(target_url, target_host, probability, most_similar_trusted, reasons)

            return {"is_phishing": is_phishing, "domain": target_host, "probability": probability,
                    "similar_to": most_similar_trusted, "reasons": reasons, "indicators": indicators,
                    "sensitivity": effective_sensitivity, "user_sensitivity": user_sensitivity,
                    "threshold": PHISH_THRESHOLD} # Also return the threshold for clarity
        except HTTPException: raise
        except Exception as e:
            print(f"\n[CRITICAL ERROR] Check failed for URL: {target_url}"); traceback.print_exc()
            raise HTTPException(status_code=500, detail={"error": "Processing error", "message": str(e)})

    # ######################################
    # ### END OF FULL CODE FIX ###
    # ######################################

# --- Initialize the Detector Core ---
detector = PhishDetector()

@app.on_event("startup")
async def startup_event():
    print("FastAPI Startup: Launching async trusted list refresher.")
    asyncio.create_task(detector._trusted_refresher_worker())

# --- ROUTING ---

# --- MODIFIED --- Dependencies for auth
async def require_authenticated(request: Request):
    """Dependency to check if user is logged in (admin or normal)."""
    if not request.session.get("authenticated"):
        raise RedirectResponse(url=app.url_path_for("login"), status_code=status.HTTP_302_FOUND)
    return request.session

async def require_admin(request: Request):
    """Dependency to check if user is logged in AND is an admin."""
    session = await require_authenticated(request)
    if not session.get("is_admin"):
        # If authenticated but NOT admin, redirect to LOGIN page
        # to allow them to log in as an admin.
        print(f"Admin access denied for user: {session.get('username')}. Redirecting to login.")
        raise RedirectResponse(url=app.url_path_for("login"), status_code=status.HTTP_302_FOUND)
    return session.get("username")


# --- Ping (unchanged) ---
@app.get("/ping")
async def ping():
    health = detector.get_health_status()
    list_data = detector.get_list_data() # Get counts together
    return {"status": "ok",
            "trusted_count": list_data["global_count"],
            "user_trusted_count": len(list_data["user_trusted"]),
            "user_blacklist_count": len(list_data["user_blacklist"]), # --- NEW ---
            "server_sensitivity": detector.server_sensitivity,
            "fuzzy_lib": FUZZY_LIB,
            "health": health}

# --- Core Check API (unchanged) ---
@app.post("/check_link")
async def check_link_api(request: Request):
    try: data = await request.json(); url = data.get("url"); user_sensitivity = data.get("user_sensitivity")
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not url: return JSONResponse({"error": "URL not provided"}, status_code=400)
    try: result = await detector.check_link(url, user_sensitivity); return JSONResponse(result)
    except HTTPException as he: return JSONResponse(he.detail, status_code=he.status_code)
    except Exception: return JSONResponse({"is_phishing": False, "error": "Internal API error"}, status_code=500)

async def _scan_links(text: str, include_redirects: bool, caps: Dict[str, Any]) -> Dict[str, Any]:
    if include_redirects and not caps.get("panel", {}).get("redirect_chain", False):
        include_redirects = False

    links = _extract_links(text)
    results = []
    phishing_count = 0
    safe_count = 0

    async def _scan_one(url: str):
        res = await detector.check_link(url)
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

    for url in links:
        try:
            item = await _scan_one(url)
        except Exception as e:
            item = {
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
        results.append(item)
        if item["status"] == "PHISHING":
            phishing_count += 1
        elif item["status"] == "SAFE":
            safe_count += 1

    history_entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(results),
        "phishing": phishing_count,
        "safe": safe_count,
    }
    detector.add_scan_history(history_entry)

    return {
        "links_found": len(links),
        "summary": history_entry,
        "results": results,
    }

@app.post("/api/scan_text", dependencies=[Depends(require_authenticated)])
async def api_scan_text(request: Request):
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

    result = await _scan_links(text, include_redirects, caps)
    return JSONResponse(result)

@app.post("/api/scan_file", dependencies=[Depends(require_authenticated)])
async def api_scan_file(request: Request, file: UploadFile = File(...), include_redirects: bool = Form(False)):
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

    result = await _scan_links(text, include_redirects, caps)
    return JSONResponse(result)

@app.get("/api/scan_history", dependencies=[Depends(require_authenticated)])
async def api_scan_history(request: Request):
    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("scan_text", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)
    return JSONResponse({"history": detector.get_scan_history()})

@app.get("/api/export_scan_history", dependencies=[Depends(require_authenticated)])
async def api_export_scan_history(request: Request):
    session = request.session
    caps = _get_caps_for_session(session)
    if not caps.get("panel", {}).get("export_history", False):
        return JSONResponse({"error": "Insufficient rank"}, status_code=403)
    history = detector.get_scan_history(limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["time", "total", "phishing", "safe"])
    for row in history:
        writer.writerow([row.get("time"), row.get("total"), row.get("phishing"), row.get("safe")])
    csv_data = output.getvalue()
    headers = {"Content-Disposition": "attachment; filename=scan_history.csv"}
    return HTMLResponse(content=csv_data, headers=headers, media_type="text/csv")

# --- Public Whitelist API (unchanged for now, admin handles this via form) ---
@app.post("/add_trusted")
async def add_trusted_api(request: Request):
    pass
@app.post("/remove_trusted")
async def remove_trusted_api(request: Request):
    pass
# --- Report API (unchanged) ---
@app.post("/report_phish")
async def report_phish_api(request: Request): 
    pass
# --- Index Page (unchanged) ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    context = {"request": request, "extension_download_path": detector.get_extension_path()}
    return templates.TemplateResponse("index.html", context)

# --- Admin ---

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
    global admin_users_db, normal_users_db
    
    # 1. Check Admins
    admin_user_data = admin_users_db.get(username)
    if admin_user_data:
        # User is in the admin list. Check password.
        if admin_user_data.get("password") == password: # Simple comparison for now
            request.session["authenticated"] = True
            request.session["is_admin"] = True
            request.session["username"] = username # Store username
            request.session["display_name"] = admin_user_data.get("display_name", username) # Store display name
            request.session["rank"] = "admin"
            print(f"Admin login successful: {username}")
            return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)
        else:
            # Admin user found, but password was wrong. FAIL immediately.
            # Do NOT proceed to check the normal user list.
            print(f"Admin login failed (wrong password): {username}")
            context = {"request": request, "error": "نام کاربری یا رمز عبور اشتباه است."}
            return templates.TemplateResponse("login.html", context, status_code=401)

    # 2. Check Normal Users
    # Only run this check if the user was NOT found in the admin list
    normal_user_data = normal_users_db.get(username)
    if normal_user_data and normal_user_data.get("password") == password: # Simple comparison for now
        request.session["authenticated"] = True
        request.session["is_admin"] = False
        request.session["username"] = username # Store username
        request.session["display_name"] = normal_user_data.get("display_name", username) # Store display name
        request.session["rank"] = _normalize_rank(normal_user_data.get("rank"))
        return RedirectResponse(url=app.url_path_for("user_panel"), status_code=status.HTTP_302_FOUND)

    # 3. Failed (User not in admin list AND (not in normal list OR wrong pass for normal list))
    print(f"Login failed for user: {username}")
    context = {"request": request, "error": "نام کاربری یا رمز عبور اشتباه است."}
    return templates.TemplateResponse("login.html", context, status_code=401)


# --- NEW --- API Login for Extension
@app.post("/api/extension_login")
async def api_extension_login(request: Request):
    global normal_users_db, admin_users_db
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
    except Exception:
        return JSONResponse({"success": False, "error": "Invalid request"}, status_code=400)

    # Check normal users first
    user_data = normal_users_db.get(username)
    if user_data and user_data.get("password") == password:
        rank = _normalize_rank(user_data.get("rank"))
        caps = RANK_CAPS[rank]
        return JSONResponse({
            "success": True,
            "displayName": user_data.get("display_name", username),
            "rank": rank,
            "isAdmin": False,
            "capabilities": caps,
        })
        
    # Optional: Allow admins to log in to extension as well
    admin_data = admin_users_db.get(username)
    if admin_data and admin_data.get("password") == password:
         return JSONResponse({
             "success": True,
             "displayName": admin_data.get("display_name", username) + " (Admin)",
             "rank": "admin",
             "isAdmin": True,
             "capabilities": RANK_CAPS["admin"],
         })

    return JSONResponse({"success": False, "error": "نام کاربری یا رمز عبور اشتباه است."}, status_code=401)


@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("username", "Unknown")
    request.session.clear() # Clear all session data
    print(f"User logout: {username}")
    return RedirectResponse(url=app.url_path_for("index"), status_code=status.HTTP_302_FOUND)

# --- MODIFIED --- Admin page context includes more data
@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request, admin_username: str = Depends(require_admin)):
    list_data = detector.get_list_data()
    reports = detector.get_reports()
    global admin_users_db, normal_users_db # Access user dbs

    context = {
        "request": request,
        "trusted_count": list_data["global_count"],
        "user_trusted": list_data["user_trusted"],
        "user_blacklist": list_data["user_blacklist"], # --- NEW ---
        "recent": reports,
        "server_sensitivity": detector.server_sensitivity,
        "current_extension_file": detector.extension_filename,
        "server_health": detector.get_health_status(),
        "admin_display_name": request.session.get("display_name", admin_username), # --- NEW --- Welcome message name
        "all_admin_users": admin_users_db, # --- NEW --- Pass users for management
        "all_normal_users": normal_users_db # --- NEW --- Pass normal users
    }
    return templates.TemplateResponse("admin.html", context)

# --- NEW --- User Panel Endpoint
@app.get("/userpanel", response_class=HTMLResponse)
async def user_panel(request: Request, session: dict = Depends(require_authenticated)):
    list_data = detector.get_list_data()
    reports = detector.get_reports()
    caps = _get_caps_for_session(session)
    rank = "admin" if session.get("is_admin") else _normalize_rank(session.get("rank"))

    context = {
        "request": request,
        "trusted_count": list_data["global_count"],
        "user_trusted": list_data["user_trusted"],
        "user_blacklist": list_data["user_blacklist"],
        "recent": reports,
        "server_sensitivity": detector.server_sensitivity,
        "server_health": detector.get_health_status(),
        "admin_display_name": session.get("display_name", session.get("username")), # Use display name
        "caps": caps,
        "user_rank": rank,
        # Note: No system-level data like users or extension files is passed
    }
    # Render a NEW template 'userpanel.html'
    return templates.TemplateResponse("userpanel.html", context)


# --- Admin POST Endpoints (Some are new) ---

@app.post("/admin/upload_extension", dependencies=[Depends(require_admin)])
async def admin_upload_extension(request: Request, extension_file: UploadFile = File(...)):
    if not extension_file.filename or not extension_file.filename.endswith(('.zip', '.crx')): # Basic validation
        print("Upload failed: Invalid file type or no filename.")
        # Optionally add a message to the session to show on redirect
        return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

    safe_filename = f"{int(time.time())}_{os.path.basename(extension_file.filename)}" # Sanitize filename
    file_path = os.path.join(detector.EXTENSION_UPLOAD_DIR, safe_filename)
    try:
        contents = await extension_file.read()
        def _save_file_and_cleanup():
            with open(file_path, "wb") as buffer: buffer.write(contents)
            detector._save_extension_file_info(safe_filename)
            detector._cleanup_old_extension_files(safe_filename)
        await asyncio.to_thread(_save_file_and_cleanup)
        print(f"Extension file uploaded: {safe_filename}")
    except Exception as e: print(f"File upload failed: {e}")
    return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)


# --- These actions might be used by the user panel too.
# --- Let's make them require 'require_authenticated' instead of 'require_admin'
# --- This allows normal users to manage their OWN lists.

@app.post("/admin/add_trusted", dependencies=[Depends(require_authenticated)])
async def admin_add_trusted_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "whitelist_manage")
    success = await asyncio.to_thread(detector.add_user_trusted, site)
    print(f"User {request.session.get('username')} added trusted: {site} (Success: {success})")
    # Redirect back to REFERER (admin or userpanel)
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_trusted", dependencies=[Depends(require_authenticated)])
async def admin_remove_trusted_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "whitelist_manage")
    success = await asyncio.to_thread(detector.remove_user_trusted, site)
    print(f"User {request.session.get('username')} removed trusted: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

# --- NEW --- Blacklist endpoints (also for all authenticated users)
@app.post("/admin/add_blacklist", dependencies=[Depends(require_authenticated)])
async def admin_add_blacklist_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "blacklist_manage")
    success = await asyncio.to_thread(detector.add_user_blacklist, site)
    print(f"User {request.session.get('username')} added blacklist: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_blacklist", dependencies=[Depends(require_authenticated)])
async def admin_remove_blacklist_form(request: Request, site: str = Form(...)):
    _require_panel_cap(request.session, "blacklist_manage")
    success = await asyncio.to_thread(detector.remove_user_blacklist, site)
    print(f"User {request.session.get('username')} removed blacklist: {site} (Success: {success})")
    redirect_url = request.headers.get("referer", app.url_path_for("admin"))
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

# --- Sensitivity and Analyze are ADMIN-ONLY ---

@app.post("/admin/set_sensitivity", dependencies=[Depends(require_admin)])
async def admin_set_sensitivity(request: Request, sensitivity: int = Form(...)):
    await asyncio.to_thread(detector.set_server_sensitivity, sensitivity)
    return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

# --- NEW --- Manual Analyze endpoint (ADMIN ONLY)
@app.post("/admin/analyze_url", dependencies=[Depends(require_admin)])
async def admin_analyze_url(request: Request):
    try: data = await request.json(); url = data.get("url")
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not url: return JSONResponse({"error": "URL not provided"}, status_code=400)
    try:
        # We don't need user sensitivity here, use server default
        result = await detector.check_link(url)
        return JSONResponse(result)
    except HTTPException as he: return JSONResponse(he.detail, status_code=he.status_code)
    except Exception as e: return JSONResponse({"is_phishing": False, "error": f"Analysis error: {e}"}, status_code=500)

# --- NEW --- Backup endpoints (ADMIN ONLY)
@app.get("/admin/backup_whitelist", dependencies=[Depends(require_admin)])
async def admin_backup_whitelist():
    filepath = detector.USER_TRUSTED_FILE
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type='application/json', filename='user_trusted_backup.json')
    else:
        return JSONResponse({"error": "Whitelist file not found"}, status_code=404)

@app.get("/admin/backup_logs", dependencies=[Depends(require_admin)])
async def admin_backup_logs():
    reports = await asyncio.to_thread(detector.get_reports, limit=10000) # Get all reports for backup
    # Return as JSON directly
    return JSONResponse(content=reports, headers={"Content-Disposition": "attachment; filename=phishguard_logs_backup.json"})

# --- NEW --- Purge endpoint (ADMIN ONLY)
@app.post("/admin/purge_logs", dependencies=[Depends(require_admin)])
async def admin_purge_logs():
    try:
        await asyncio.to_thread(detector.purge_reports)
        return JSONResponse({"status": "success"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)

# --- NEW --- User Management Endpoints (ADMIN ONLY)
@app.post("/admin/add_user", dependencies=[Depends(require_admin)])
async def admin_add_user(request: Request,
                         new_username: str = Form(...),
                         new_password: str = Form(...),
                         display_name: str = Form(...)):
    global admin_users_db
    if not new_username or not new_password or not display_name:
        # Add error message to session maybe
        return RedirectResponse(url=app.url_path_for("admin"), status_code=status.HTTP_302_FOUND)

    with admin_users_lock:
        if new_username in admin_users_db:
            # Username already exists, handle error (e.g., flash message)
            print(f"Add admin user failed: {new_username} already exists.")
        else:
            # IMPORTANT: Hash the password in production!
            # hashed_pass = hashlib.sha256(new_password.encode()).hexdigest()
            admin_users_db[new_username] = {"password": new_password, "display_name": display_name}
            _save_user_db(ADMIN_USERS_FILE, admin_users_db)
            print(f"Admin user added: {new_username}")
    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND) # Redirect back to system tab

@app.post("/admin/remove_user", dependencies=[Depends(require_admin)])
async def admin_remove_user(request: Request, username_to_remove: str = Form(...)):
    global admin_users_db
    current_user = request.session.get("username")

    if username_to_remove == current_user:
        # Cannot remove self
        print("Remove admin user failed: Cannot remove self.")
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)
    if len(admin_users_db) <= 1:
        # Cannot remove the last admin
        print("Remove admin user failed: Cannot remove the last admin.")
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    with admin_users_lock:
        if username_to_remove in admin_users_db:
            del admin_users_db[username_to_remove]
            _save_user_db(ADMIN_USERS_FILE, admin_users_db)
            print(f"Admin user removed: {username_to_remove}")
        else:
            print(f"Remove admin user failed: {username_to_remove} not found.")

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)


# --- NEW --- Normal User Management Endpoints (ADMIN ONLY)
@app.post("/admin/add_normal_user", dependencies=[Depends(require_admin)])
async def admin_add_normal_user(request: Request,
                                new_normal_username: str = Form(...),
                                new_normal_password: str = Form(...),
                                normal_display_name: str = Form(...),
                                normal_rank: str = Form(DEFAULT_RANK)):
    global normal_users_db
    if not new_normal_username or not new_normal_password or not normal_display_name:
        return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    with normal_users_lock:
        if new_normal_username in normal_users_db:
            print(f"Add normal user failed: {new_normal_username} already exists.")
        else:
            # IMPORTANT: Hash the password in production!
            rank = _normalize_rank(normal_rank)
            normal_users_db[new_normal_username] = {
                "password": new_normal_password,
                "display_name": normal_display_name,
                "rank": rank,
            }
            _save_user_db(NORMAL_USERS_FILE, normal_users_db)
            print(f"Normal user added: {new_normal_username}")
    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/remove_normal_user", dependencies=[Depends(require_admin)])
async def admin_remove_normal_user(request: Request, username_to_remove_normal: str = Form(...)):
    global normal_users_db

    # No self-check needed as admin is not in this list
    if len(normal_users_db) <= 1:
        # Optional: prevent removing last normal user
        print("Remove normal user failed: Cannot remove the last user (optional check).")
        # return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

    with normal_users_lock:
        if username_to_remove_normal in normal_users_db:
            del normal_users_db[username_to_remove_normal]
            _save_user_db(NORMAL_USERS_FILE, normal_users_db)
            print(f"Normal user removed: {username_to_remove_normal}")
        else:
            print(f"Remove normal user failed: {username_to_remove_normal} not found.")

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)

@app.post("/admin/update_normal_user_rank", dependencies=[Depends(require_admin)])
async def admin_update_normal_user_rank(
    request: Request,
    username_to_update: str = Form(...),
    normal_rank: str = Form(DEFAULT_RANK),
):
    global normal_users_db
    rank = _normalize_rank(normal_rank)
    with normal_users_lock:
        user = normal_users_db.get(username_to_update)
        if user:
            user["rank"] = rank
            _save_user_db(NORMAL_USERS_FILE, normal_users_db)
            print(f"Normal user rank updated: {username_to_update} -> {rank}")
        else:
            print(f"Update rank failed: {username_to_update} not found.")

    return RedirectResponse(url=app.url_path_for("admin") + "?tab=system", status_code=status.HTTP_302_FOUND)


# --- Shutdown (ADMIN ONLY) ---
@app.post("/admin/shutdown", dependencies=[Depends(require_admin)])
async def admin_shutdown():
    print("--- 🛑 Server Shutdown Request Received (Admin) 🛑 ---")
    def shutdown_server(): time.sleep(0.5); os._exit(0)
    threading.Thread(target=shutdown_server).start()
    return JSONResponse({"status": "Server shutting down!"})

if __name__ == "__main__":
    # Ensure necessary files exist
    for f in [TRUSTED_GLOBAL_CACHE, USER_TRUSTED_FILE, USER_BLACKLIST_FILE, ADMIN_USERS_FILE, NORMAL_USERS_FILE]:
        if not os.path.exists(f):
            print(f"Creating empty file: {f}")
            with open(f, 'w') as fp:
                if f == ADMIN_USERS_FILE or f == NORMAL_USERS_FILE: json.dump({}, fp) 
                else: json.dump([], fp) 

    host = os.environ.get("PHISH_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    print(f"Server starting on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
