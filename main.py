"""
Universal JS Analyzer - Single File (Web + Telegram Bot)
Run: python main.py
Works on Render as a Web Service (Flask + Bot polling in background thread)

⚠️ Sirf apni website test karne ke liye use karo.
"""

import os
import re
import json
import threading
import asyncio
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


# ==================== CONFIG ====================
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

DOWNLOAD_TIMEOUT = 20
MAX_JS_SIZE = 15 * 1024 * 1024
MAX_FILES = 40

PORT = int(os.environ.get("PORT", 5000))
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
ADMIN_IDS = [int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip()]


# ==================== SEARCH PATTERNS (SAME LOGIC) ====================
SEARCH_PATTERNS = {
    # ---------- ENCRYPTION KEYS ----------
    "AES_KEY": [
        r'(?:AES_KEY|aesKey|AesKey|AESKEY)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{16,64})["\']',
        r'(?:AES_KEY|aesKey)\s*[:=]\s*[`"\']([^`"\']{16,64})[`"\']',
    ],
    "AES_IV": [
        r'(?:AES_IV|aesIv|AesIV|iv|IV)\s*[:=]\s*["\']([A-Za-z0-9+/=]{16})["\']',
    ],
    "SECRET_KEY": [
        r'(?:SECRET_KEY|secretKey|SecretKey|secret_key)\s*[:=]\s*["\']([^"\']{8,128})["\']',
    ],
    "SECRET_CODE": [
        r'(?:SECRET_CODE|secretCode|SecretCode)\s*[:=]\s*["\']([^"\']{8,128})["\']',
    ],
    "API_KEY": [
        r'(?:API_KEY|apiKey|ApiKey|api_key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,128})["\']',
    ],
    "ACCESS_TOKEN": [
        r'(?:ACCESS_TOKEN|accessToken|access_token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
    ],
    "BEARER_TOKEN": [
        r'(?:BEARER|bearer|Bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
    ],
    "JWT_SECRET": [
        r'(?:JWT_SECRET|jwtSecret|JWT_KEY|jwtKey)\s*[:=]\s*["\']([^"\']{8,128})["\']',
    ],
    "SALT": [
        r'(?:salt|SALT|Sault|SAULT|saltValue|salt_value)\s*[:=]\s*["\']([^"\']{4,128})["\']',
    ],
    "PRIVATE_KEY": [
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]{100,3000}?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----',
    ],
    "PUBLIC_KEY": [
        r'-----BEGIN PUBLIC KEY-----[\s\S]{100,3000}?-----END PUBLIC KEY-----',
    ],
    "HMAC_KEY": [
        r'(?:HMAC|hmac|HMAC_KEY)\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,128})["\']',
    ],
    "ENCRYPTION_KEY": [
        r'(?:ENCRYPTION_KEY|encryptionKey|encryption_key)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{16,128})["\']',
    ],
    "SECRET_KEY_GENERIC": [
        r'(?:secret|Secret)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-#@!$%^&*]{8,128})["\']',
    ],
    "BASIC_AUTH": [
        r'Basic\s+([A-Za-z0-9+/=]{20,})',
    ],

    # ---------- API ENDPOINTS ----------
    "API_ENDPOINTS": [
        r'["\']((?:https?://)?[a-zA-Z0-9\-\.]+/(?:api|v\d|rest|graphql)/[^"\'\s]{3,100})["\']',
        r'["\'](/api/[^"\'\s]{3,100})["\']',
        r'["\'](/v\d/[^"\'\s]{3,100})["\']',
        r'["\'](/[a-z\-]+/api/[^"\'\s]{3,100})["\']',
    ],
    "FULL_URLS": [
        r'["\'](https?://[a-zA-Z0-9\-\._/]+(?:\?[^"\'\s]*)?)["\']',
    ],
    "WEBSOCKET_URLS": [
        r'["\'](wss?://[a-zA-Z0-9\-\._/:]+)["\']',
    ],

    # ---------- CRYPTO FUNCTIONS ----------
    "CRYPTO_FUNCTIONS": [
        r'function\s+(\w*(?:encrypt|decrypt|cipher|hash|sign|verify)\w*)\s*\([^)]*\)\s*\{[^}]{0,2000}\}',
        r'(\w*(?:encrypt|decrypt)\w*)\s*[:=]\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{[^}]{0,2000}\}',
    ],
    "CRYPTOJS_USAGE": [
        r'CryptoJS\.(\w+)\.(encrypt|decrypt|hash|sign)\s*\([^)]{0,200}\)',
        r'(?:CryptoJS|crypto)\.(AES|DES|TripleDES|RC4|SHA256|SHA1|MD5|HmacSHA256)',
    ],
    "BASE64_USAGE": [
        r'\b(?:atob|btoa)\s*\([^)]{0,200}\)',
    ],
    "PBKDF2_USAGE": [
        r'PBKDF2\s*\([^)]{0,200}\)[^;]{0,300}',
    ],
    "AES_USAGE": [
        r'\.AES\.(?:encrypt|decrypt)\s*\([^)]{0,300}\)',
    ],
    "RSA_USAGE": [
        r'\.(?:RSA|PublicKey|PrivateKey)\.(?:encrypt|decrypt|sign|verify)\s*\([^)]{0,300}\)',
    ],

    # ---------- CREDENTIALS ----------
    "USERNAME": [
        r'(?:username|userName|USERNAME|user_name)\s*[:=]\s*["\']([^"\']{3,64})["\']',
    ],
    "PASSWORD": [
        r'(?:password|passwd|pwd|PASSWORD)\s*[:=]\s*["\']([^"\']{4,64})["\']',
    ],

    # ---------- THIRD PARTY ----------
    "GITHUB_TOKENS": [
        r'gh[pousr]_[A-Za-z0-9]{36,255}',
    ],
    "GOOGLE_API_KEY": [
        r'AIza[0-9A-Za-z\-_]{35}',
    ],
    "FIREBASE_URL": [
        r'https://[a-z0-9\-]+\.firebaseio\.com',
        r'https://[a-z0-9\-]+\.firebaseapp\.com',
    ],
    "AWS_KEY": [
        r'AKIA[0-9A-Z]{16}',
    ],
    "STRIPE_KEY": [
        r'sk_live_[0-9a-zA-Z]{24,}',
        r'pk_live_[0-9a-zA-Z]{24,}',
    ],
    "TWILIO_KEY": [
        r'SK[0-9a-fA-F]{32}',
    ],
    "SENDGRID_KEY": [
        r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
    ],
    "SLACK_TOKEN": [
        r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    ],
    "IP_ADDRESS": [
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ],
    "EMAIL": [
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    ],
    "PHONE": [
        r'(?:\+91[\-\s]?)?[6-9]\d{9}\b',
    ],
    "AADHAAR_LIKE": [
        r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
    ],
}

CATEGORY_GROUPS = {
    "🔐 ENCRYPTION KEYS": ["AES_KEY", "AES_IV", "SECRET_KEY", "SECRET_CODE",
                           "ENCRYPTION_KEY", "HMAC_KEY", "SALT", "SECRET_KEY_GENERIC"],
    "🔑 API KEYS & TOKENS": ["API_KEY", "ACCESS_TOKEN", "BEARER_TOKEN", "JWT_SECRET"],
    "🔏 RSA KEYS": ["PUBLIC_KEY", "PRIVATE_KEY", "BASIC_AUTH"],
    "🌐 API ENDPOINTS": ["API_ENDPOINTS", "FULL_URLS", "WEBSOCKET_URLS"],
    "⚙️ CRYPTO USAGE": ["CRYPTO_FUNCTIONS", "CRYPTOJS_USAGE", "AES_USAGE",
                        "RSA_USAGE", "PBKDF2_USAGE", "BASE64_USAGE"],
    "👤 CREDENTIALS": ["USERNAME", "PASSWORD"],
    "🔍 THIRD-PARTY KEYS": ["GITHUB_TOKENS", "GOOGLE_API_KEY", "FIREBASE_URL",
                            "AWS_KEY", "STRIPE_KEY", "TWILIO_KEY", "SENDGRID_KEY", "SLACK_TOKEN"],
    "📞 OTHER": ["EMAIL", "PHONE", "IP_ADDRESS", "AADHAAR_LIKE"],
}


# ==================== UTILITY FUNCTIONS ====================
def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def is_js_url(url):
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith('.js') or path.endswith('.mjs') or 'javascript' in path


def get_page(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15, verify=False)
        return r.text
    except Exception:
        return None


def extract_js_urls(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    js_urls = set()

    for script in soup.find_all('script', src=True):
        js_urls.add(urljoin(base_url, script['src']))

    for script in soup.find_all('script'):
        if script.string:
            for m in re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', script.string):
                js_urls.add(urljoin(base_url, m))
            for m in re.findall(r'["\'](https?://[^"\']+\.js(?:\?[^"\']*)?)["\']', script.string):
                js_urls.add(m)

    for link in soup.find_all('link'):
        href = link.get('href', '')
        if href.endswith('.js') or href.endswith('.mjs'):
            js_urls.add(urljoin(base_url, href))

    js_urls = {u for u in js_urls if is_js_url(u)}
    return list(js_urls)


def download_js_content(js_url):
    """Download JS content in-memory (no disk save - hosting friendly)"""
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=DOWNLOAD_TIMEOUT,
                          verify=False, stream=True)
        if r.status_code != 200:
            return None

        content_length = int(r.headers.get('Content-Length', 0))
        if content_length > MAX_JS_SIZE:
            return None

        content = r.content
        if len(content) > MAX_JS_SIZE:
            return None

        return content.decode('utf-8', errors='ignore')
    except Exception:
        return None


def analyze_content(content):
    """Analyze JS content for all patterns"""
    findings = {}

    for category, patterns in SEARCH_PATTERNS.items():
        matches = set()
        for pattern in patterns:
            try:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    if m.groups():
                        val = m.group(1)
                    else:
                        val = m.group(0)
                    val = val.strip()
                    if 3 < len(val) < 5000:
                        matches.add(val)
            except re.error:
                continue

        if matches:
            findings[category] = sorted(matches)

    return findings


def extract_function_code(content, func_name):
    patterns = [
        rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{([\s\S]{{0,2000}}?)\n\}}',
        rf'{re.escape(func_name)}\s*[:=]\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{{([\s\S]{{0,2000}}?)\n\}}',
    ]
    for pattern in patterns:
        m = re.search(pattern, content)
        if m:
            return m.group(0)[:1500]
    return None


# ==================== MAIN ANALYSIS ====================
def analyze_website(url):
    """Full analysis pipeline - returns structured result dict"""
    target_url = normalize_url(url)
    result = {
        "target": target_url,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "js_files_found": 0,
        "js_files_analyzed": 0,
        "all_findings": {},
        "per_file": {},
        "functions": [],
        "error": None,
    }

    html = get_page(target_url)
    if html is None:
        result["error"] = "Failed to fetch page. Check the URL."
        return result

    js_urls = extract_js_urls(html, target_url)
    result["js_files_found"] = len(js_urls)

    # Analyze inline scripts if no external JS found
    if not js_urls:
        soup = BeautifulSoup(html, 'html.parser')
        inline = "\n".join(s.string for s in soup.find_all('script') if s.string)
        if inline:
            findings = analyze_content(inline)
            result["per_file"]["INLINE_SCRIPTS"] = findings
            for k, v in findings.items():
                result["all_findings"].setdefault(k, set()).update(v)

    js_urls = js_urls[:MAX_FILES]

    for js_url in js_urls:
        content = download_js_content(js_url)
        if not content:
            continue

        result["js_files_analyzed"] += 1
        fname = os.path.basename(urlparse(js_url).path) or js_url
        if '?' in fname:
            fname = fname.split('?')[0]

        findings = analyze_content(content)
        result["per_file"][fname] = findings

        for k, v in findings.items():
            result["all_findings"].setdefault(k, set()).update(v)

        # crypto function extraction (max 10 total)
        if len(result["functions"]) < 10:
            crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'hash', 'sign']
            func_pattern = r'function\s+(\w*(?:' + '|'.join(crypto_keywords) + r')\w*)\s*\([^)]*\)\s*\{'
            for m in re.finditer(func_pattern, content, re.IGNORECASE):
                func_name = m.group(1)
                code = extract_function_code(content, func_name)
                if code:
                    result["functions"].append({
                        "file": fname, "name": func_name, "code": code[:800]
                    })
                if len(result["functions"]) >= 10:
                    break

    result["all_findings"] = {k: sorted(v) for k, v in result["all_findings"].items()}
    return result


def format_report(result, max_per_category=15):
    """Convert result dict into a readable plain-text report"""
    lines = []
    lines.append("=" * 60)
    lines.append("  UNIVERSAL JS ANALYZER - REPORT")
    lines.append("=" * 60)
    lines.append(f"Target : {result['target']}")
    lines.append(f"Time   : {result['time']}")

    if result["error"]:
        lines.append(f"\n❌ ERROR: {result['error']}")
        return "\n".join(lines)

    lines.append(f"JS Files Found    : {result['js_files_found']}")
    lines.append(f"JS Files Analyzed : {result['js_files_analyzed']}")

    findings = result["all_findings"]
    any_found = False

    for group_name, keys in CATEGORY_GROUPS.items():
        group_lines = []
        for key in keys:
            if key in findings and findings[key]:
                any_found = True
                vals = findings[key]
                group_lines.append(f"\n[{key}] ({len(vals)} found)")
                for v in vals[:max_per_category]:
                    display = v if len(v) <= 150 else v[:150] + "..."
                    group_lines.append(f"  -> {display}")
                if len(vals) > max_per_category:
                    group_lines.append(f"  ... and {len(vals) - max_per_category} more")

        if group_lines:
            lines.append("\n" + "-" * 60)
            lines.append(group_name)
            lines.append("-" * 60)
            lines.extend(group_lines)

    if not any_found:
        lines.append("\n✅ No sensitive patterns found.")

    if result["functions"]:
        lines.append("\n" + "-" * 60)
        lines.append("⚙️ CRYPTO FUNCTIONS CODE")
        lines.append("-" * 60)
        for f in result["functions"]:
            lines.append(f"\nFile: {f['file']}  |  Function: {f['name']}")
            lines.append(f['code'])

    return "\n".join(lines)


# ==================== FLASK WEB APP ====================
app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>JS Analyzer - Self Test Tool</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { background:#0f0f0f; color:#e0e0e0; font-family: monospace; padding: 20px; }
    h2 { color:#00e5ff; }
    input[type=text] { width: 70%; padding: 10px; font-size: 15px; border-radius:5px; border:1px solid #444; background:#1a1a1a; color:#fff; }
    button { padding: 10px 20px; font-size: 15px; background:#00c853; border:none; border-radius:5px; color:#000; cursor:pointer; font-weight:bold; }
    button:hover { background:#00e676; }
    pre { background:#1a1a1a; padding:15px; border-radius:8px; overflow-x:auto; white-space: pre-wrap; word-wrap: break-word; border: 1px solid #333; }
    .loading { color:#ffab00; }
  </style>
</head>
<body>
  <h2>🔍 Universal JS Analyzer - Self Test</h2>
  <p>Apni website ka URL daalo aur scan karo (JS files me secrets/keys/endpoints dhundhega)</p>
  <form method="post" action="/scan">
    <input type="text" name="url" placeholder="https://yourdomain.com" required value="{{ last_url or '' }}">
    <button type="submit">🔎 Scan Now</button>
  </form>

  {% if report %}
    <h3 style="color:#69f0ae;">📊 Report:</h3>
    <pre>{{ report }}</pre>
  {% endif %}

  <p style="margin-top:30px; color:#666; font-size:12px;">
    ⚠️ Sirf apni website test karo. Isse third-party sites pe use mat karo.
  </p>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PAGE, report=None, last_url=None)


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template_string(HTML_PAGE, report="❌ URL required", last_url=None)

    result = analyze_website(url)
    report = format_report(result)
    return render_template_string(HTML_PAGE, report=report, last_url=url)


@app.route("/health")
def health():
    return "OK"


# ==================== TELEGRAM BOT (ADMIN ONLY) ====================
def is_admin(user_id):
    if not ADMIN_IDS:
        return False
    return user_id in ADMIN_IDS


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("❌ Access denied. Admin only.")
        return
    await update.message.reply_text(
        "👋 Welcome Admin!\n\nUse:\n/scan <your-website-url>\n\nExample:\n/scan https://mysite.com"
    )


async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("❌ Access denied. Admin only.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /scan https://yourdomain.com")
        return

    url = context.args[0]
    await update.message.reply_text(f"🔍 Scanning: {url}\nPlease wait...")

    try:
        result = analyze_website(url)
        report = format_report(result)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        return

    # Telegram message limit ~4096 chars, chunk it
    max_len = 3800
    for i in range(0, len(report), max_len):
        chunk = report[i:i + max_len]
        await update.message.reply_text(chunk)


def run_bot():
    if not BOT_TOKEN:
        print("[!] BOT_TOKEN not set - Telegram bot skipped (website will still work)")
        return
    if not ADMIN_IDS:
        print("[!] ADMIN_IDS not set - bot will deny everyone")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start_cmd))
    application.add_handler(CommandHandler("scan", scan_cmd))

    print("[+] Telegram bot starting (polling mode)...")
    application.run_polling(stop_signals=None)


# ==================== ENTRY POINT ====================
def start_bot_thread():
    if BOT_TOKEN:
        t = threading.Thread(target=run_bot, daemon=True)
        t.start()


# Start bot thread as soon as module loads (works with gunicorn too)
start_bot_thread()

if __name__ == "__main__":
    print(f"[+] Starting Flask web app on port {PORT}...")
    app.run(host="0.0.0.0", port=PORT)
