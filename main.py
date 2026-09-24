"""
╔══════════════════════════════════════════════════════════════════╗
║            UNIVERSAL JS ANALYZER - By Abhigyan                   ║
║         Web + Telegram Bot (Single File, Render Ready)           ║
╚══════════════════════════════════════════════════════════════════╝

⚠️  ONLY use on websites you own or have explicit permission to test.
"""

import os
import re
import json
import uuid
import threading
import asyncio
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string, Response

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
MAX_JS_SIZE = 15 * 1024 * 1024   # 15 MB per file
MAX_FILES = 60                    # Kept reasonable for hosted timeouts

PORT = int(os.environ.get("PORT", 5000))
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
ADMIN_IDS = [int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip()]

# In-memory cache to let web UI offer "download full report" after scan
SCAN_CACHE = {}


# ==================== SEARCH PATTERNS (ORIGINAL - UNCHANGED) ====================
SEARCH_PATTERNS = {
    # ========== ENCRYPTION KEYS ==========
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

    # ========== API ENDPOINTS ==========
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

    # ========== CRYPTO FUNCTIONS ==========
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

    # ========== CREDENTIALS ==========
    "USERNAME": [
        r'(?:username|userName|USERNAME|user_name)\s*[:=]\s*["\']([^"\']{3,64})["\']',
    ],
    "PASSWORD": [
        r'(?:password|passwd|pwd|PASSWORD)\s*[:=]\s*["\']([^"\']{4,64})["\']',
    ],

    # ========== INTERESTING ==========
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
    "🔐 ENCRYPTION KEYS": [
        "AES_KEY", "AES_IV", "SECRET_KEY", "SECRET_CODE",
        "ENCRYPTION_KEY", "HMAC_KEY", "SALT", "SECRET_KEY_GENERIC"
    ],
    "🔑 API KEYS & TOKENS": [
        "API_KEY", "ACCESS_TOKEN", "BEARER_TOKEN", "JWT_SECRET"
    ],
    "🔏 RSA KEYS": [
        "PUBLIC_KEY", "PRIVATE_KEY", "BASIC_AUTH"
    ],
    "🌐 API ENDPOINTS": [
        "API_ENDPOINTS", "FULL_URLS", "WEBSOCKET_URLS"
    ],
    "⚙️ CRYPTO FUNCTIONS": [
        "CRYPTO_FUNCTIONS", "CRYPTOJS_USAGE", "AES_USAGE",
        "RSA_USAGE", "PBKDF2_USAGE", "BASE64_USAGE"
    ],
    "👤 CREDENTIALS": [
        "USERNAME", "PASSWORD"
    ],
    "🔍 THIRD-PARTY KEYS": [
        "GITHUB_TOKENS", "GOOGLE_API_KEY", "FIREBASE_URL",
        "AWS_KEY", "STRIPE_KEY", "TWILIO_KEY", "SENDGRID_KEY", "SLACK_TOKEN"
    ],
    "📞 OTHER": [
        "EMAIL", "PHONE", "IP_ADDRESS", "AADHAAR_LIKE"
    ],
}


# ==================== UTILITY FUNCTIONS (ORIGINAL - UNCHANGED) ====================
def normalize_url(url):
    """Add https:// if missing"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def is_js_url(url):
    """Check if URL is a JS file"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith('.js') or path.endswith('.mjs') or 'javascript' in path


# ==================== FETCH & EXTRACT (ORIGINAL - UNCHANGED) ====================
def get_page(url):
    """Fetch main page"""
    try:
        r = requests.get(url, headers=HEADERS, timeout=30, verify=False)
        return r.text
    except Exception:
        return None


def extract_js_urls(html, base_url):
    """Extract all JS URLs from HTML"""
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


def download_js(js_url):
    """Download JS file content (in-memory, hosting-friendly)"""
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


# ==================== ANALYSIS (ORIGINAL - UNCHANGED) ====================
def analyze_content(content, filename):
    """Analyze JS content for all patterns"""
    findings = {}

    for category, patterns in SEARCH_PATTERNS.items():
        matches = set()
        for pattern in patterns:
            try:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    val = m.group(1) if m.groups() else m.group(0)
                    val = val.strip()
                    if 3 < len(val) < 5000:
                        matches.add(val)
            except re.error:
                continue

        if matches:
            findings[category] = sorted(matches)

    return findings


def extract_function_code(content, func_name):
    """Extract function body"""
    patterns = [
        rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{([\s\S]{{0,2000}}?)\n\}}',
        rf'{re.escape(func_name)}\s*[:=]\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{{([\s\S]{{0,2000}}?)\n\}}',
    ]

    for pattern in patterns:
        m = re.search(pattern, content)
        if m:
            return m.group(0)[:1500]
    return None


# ==================== FULL PIPELINE (ORIGINAL main() LOGIC) ====================
def run_full_analysis(target_url):
    """
    Runs the exact same 7-step pipeline as the original CLI script's main(),
    but returns a structured result dict instead of printing to console.
    """
    target_url = normalize_url(target_url)

    result = {
        "target": target_url,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "error": None,
        "html_size": 0,
        "js_urls": [],
        "js_files_found": 0,
        "js_files_analyzed": 0,
        "all_findings": {},     # global merged findings
        "per_file": {},         # STEP 4 - per-file breakdown
        "functions": [],        # STEP 7 - crypto functions code
        "quick_summary": {},    # final summary counts
    }

    # ===== STEP 1: Fetch main page =====
    html = get_page(target_url)
    if not html:
        result["error"] = "Failed to fetch page. Check the URL and try again."
        return result
    result["html_size"] = len(html)

    # ===== STEP 2: Extract JS URLs =====
    js_urls = extract_js_urls(html, target_url)
    result["js_files_found"] = len(js_urls)
    js_urls = js_urls[:MAX_FILES]
    result["js_urls"] = js_urls

    all_findings = {}
    per_file = {}

    # Analyze inline scripts if no external JS found
    if not js_urls:
        soup = BeautifulSoup(html, 'html.parser')
        inline = "\n".join(s.string for s in soup.find_all('script') if s.string)
        if inline:
            findings = analyze_content(inline, "INLINE_SCRIPTS")
            per_file["INLINE_SCRIPTS"] = findings
            for k, v in findings.items():
                all_findings.setdefault(k, set()).update(v)

    # ===== STEP 3 & 4: Download + Analyze each JS file =====
    downloaded_contents = []  # (filename, content, url) - for step 7 reuse
    for js_url in js_urls:
        content = download_js(js_url)
        if not content:
            continue

        result["js_files_analyzed"] += 1

        fname = os.path.basename(urlparse(js_url).path) or "script.js"
        if '?' in fname:
            fname = fname.split('?')[0]

        findings = analyze_content(content, fname)
        per_file[fname] = findings
        downloaded_contents.append((fname, content, js_url))

        for k, v in findings.items():
            all_findings.setdefault(k, set()).update(v)

    result["all_findings"] = {k: sorted(v) for k, v in all_findings.items()}
    result["per_file"] = per_file

    # ===== STEP 7: Extract crypto function code =====
    crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'hash', 'sign']
    function_count = 0
    for fname, content, url in downloaded_contents:
        if function_count >= 10:
            break
        func_pattern = r'function\s+(\w*(?:' + '|'.join(crypto_keywords) + r')\w*)\s*\([^)]*\)\s*\{'
        for m in re.finditer(func_pattern, content, re.IGNORECASE):
            func_name = m.group(1)
            code = extract_function_code(content, func_name)
            if code:
                result["functions"].append({
                    "file": fname,
                    "name": func_name,
                    "code": code[:1500],
                })
                function_count += 1
            if function_count >= 10:
                break

    # ===== Quick Summary =====
    for cat in ["AES_KEY", "SECRET_KEY", "API_KEY", "PUBLIC_KEY",
                "API_ENDPOINTS", "CRYPTO_FUNCTIONS", "SALT"]:
        if cat in result["all_findings"]:
            result["quick_summary"][cat] = len(result["all_findings"][cat])

    return result


def format_text_report(result):
    """Plain-text version of the report (used for download + Telegram)"""
    lines = []
    lines.append("=" * 70)
    lines.append("  UNIVERSAL JS ANALYZER - FULL REPORT")
    lines.append("=" * 70)
    lines.append(f"Target: {result['target']}")
    lines.append(f"Time: {result['time']}")

    if result["error"]:
        lines.append(f"\nERROR: {result['error']}")
        return "\n".join(lines)

    lines.append(f"JS Files Found: {result['js_files_found']}")
    lines.append(f"JS Files Analyzed: {result['js_files_analyzed']}")

    # Grouped findings
    for group_name, keys in CATEGORY_GROUPS.items():
        group_lines = []
        for key in keys:
            vals = result["all_findings"].get(key)
            if vals:
                group_lines.append(f"\n[{key}] ({len(vals)} found)")
                for v in vals[:15]:
                    display = v if len(v) <= 150 else v[:150] + "..."
                    group_lines.append(f"  -> {display}")
                if len(vals) > 15:
                    group_lines.append(f"  ... and {len(vals)-15} more")
        if group_lines:
            lines.append("\n" + "-" * 70)
            lines.append(group_name)
            lines.append("-" * 70)
            lines.extend(group_lines)

    # Per-file breakdown
    if result["per_file"]:
        lines.append("\n" + "-" * 70)
        lines.append("PER-FILE BREAKDOWN")
        lines.append("-" * 70)
        for fname, findings in result["per_file"].items():
            total = sum(len(v) for v in findings.values())
            if total > 0:
                lines.append(f"\n{fname}")
                for key, vals in findings.items():
                    if vals:
                        lines.append(f"   - {key}: {len(vals)} found")

    # Crypto functions
    if result["functions"]:
        lines.append("\n" + "-" * 70)
        lines.append("CRYPTO FUNCTIONS CODE")
        lines.append("-" * 70)
        for f in result["functions"]:
            lines.append(f"\nFile: {f['file']}  |  Function: {f['name']}")
            lines.append(f["code"])

    # JS files list
    if result["js_urls"]:
        lines.append("\n" + "-" * 70)
        lines.append("JS FILES LIST")
        lines.append("-" * 70)
        for u in result["js_urls"]:
            lines.append(f"  {u}")

    if not result["all_findings"]:
        lines.append("\n✅ No sensitive patterns found.")

    return "\n".join(lines)


# ==================== FLASK WEB APP ====================
app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JS Analyzer - Self Test Tool</title>
<style>
  * { box-sizing: border-box; }
  body {
    background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Roboto, monospace;
    padding: 0; margin: 0;
  }
  .container { max-width: 900px; margin: 0 auto; padding: 20px; }
  header { text-align: center; padding: 25px 0 10px; }
  header h1 { color: #58a6ff; font-size: 26px; margin-bottom: 5px; }
  header p { color: #8b949e; font-size: 14px; }

  .scan-form {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 20px; margin-bottom: 25px; display: flex; gap: 10px; flex-wrap: wrap;
  }
  .scan-form input[type=text] {
    flex: 1; min-width: 220px; padding: 12px 14px; font-size: 15px;
    border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #fff;
  }
  .scan-form button {
    padding: 12px 24px; font-size: 15px; background: #238636; border: none;
    border-radius: 6px; color: #fff; cursor: pointer; font-weight: 600;
  }
  .scan-form button:hover { background: #2ea043; }
  .scan-form button:disabled { background: #444; cursor: not-allowed; }

  .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 25px; }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 14px 18px; flex: 1; min-width: 140px;
  }
  .card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
  .card .value { font-size: 20px; font-weight: 700; color: #58a6ff; margin-top: 4px; word-break: break-all; }

  details {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    margin-bottom: 12px; overflow: hidden;
  }
  summary {
    padding: 14px 18px; cursor: pointer; font-weight: 600; font-size: 15px;
    display: flex; justify-content: space-between; align-items: center;
    list-style: none;
  }
  summary::-webkit-details-marker { display: none; }
  summary .count { background: #21262d; color: #f0883e; padding: 2px 10px; border-radius: 12px; font-size: 12px; }
  .details-body { padding: 0 18px 18px; }

  .finding-block { margin-top: 14px; }
  .finding-block h4 { color: #f0883e; font-size: 13px; margin-bottom: 8px; text-transform: uppercase; }
  .finding-item {
    background: #0d1117; border-left: 3px solid #f85149; padding: 8px 12px;
    margin-bottom: 6px; border-radius: 4px; font-size: 13px; word-break: break-all;
    font-family: 'Consolas', monospace;
  }
  .finding-item.endpoint { border-left-color: #58a6ff; }
  .finding-item.other { border-left-color: #3fb950; }
  .more-note { color: #8b949e; font-size: 12px; margin-top: 4px; }

  table.file-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  table.file-table th, table.file-table td {
    text-align: left; padding: 8px 10px; border-bottom: 1px solid #30363d; font-size: 13px;
  }
  table.file-table th { color: #8b949e; text-transform: uppercase; font-size: 11px; }

  .func-block {
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px; margin-top: 12px;
  }
  .func-block .func-title { color: #a5d6ff; font-size: 13px; margin-bottom: 8px; }
  .func-block pre {
    white-space: pre-wrap; word-wrap: break-word; font-size: 12px;
    color: #c9d1d9; margin: 0; max-height: 300px; overflow-y: auto;
  }

  .empty-msg { text-align: center; color: #3fb950; padding: 20px; font-size: 15px; }
  .error-msg {
    background: #3d1418; border: 1px solid #f85149; color: #ffb3b3;
    padding: 14px 18px; border-radius: 8px; margin-bottom: 20px;
  }

  .download-btn {
    display: inline-block; margin-top: 15px; padding: 10px 20px;
    background: #1f6feb; color: #fff; text-decoration: none; border-radius: 6px;
    font-size: 14px; font-weight: 600;
  }
  .download-btn:hover { background: #388bfd; }

  footer { text-align: center; color: #484f58; font-size: 12px; padding: 30px 0 15px; }

  .js-list { max-height: 200px; overflow-y: auto; }
  .js-list div { padding: 4px 0; font-size: 12px; color: #8b949e; border-bottom: 1px dashed #21262d; word-break: break-all; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔍 Universal JS Analyzer</h1>
    <p>Apni website ka URL daalo — JS files scan hoke keys/secrets/endpoints report banegi</p>
  </header>

  <form class="scan-form" method="post" action="/scan" onsubmit="document.getElementById('btn').innerText='⏳ Scanning...'; document.getElementById('btn').disabled=true;">
    <input type="text" name="url" placeholder="https://yourdomain.com" required value="{{ last_url or '' }}">
    <button id="btn" type="submit">🔎 Scan Now</button>
  </form>

  {% if result %}
    {% if result.error %}
      <div class="error-msg">❌ {{ result.error }}</div>
    {% else %}
      <div class="cards">
        <div class="card"><div class="label">Target</div><div class="value">{{ result.target }}</div></div>
        <div class="card"><div class="label">JS Found</div><div class="value">{{ result.js_files_found }}</div></div>
        <div class="card"><div class="label">JS Analyzed</div><div class="value">{{ result.js_files_analyzed }}</div></div>
        <div class="card"><div class="label">Scan Time</div><div class="value">{{ result.time }}</div></div>
      </div>

      {% if result.js_urls %}
      <details>
        <summary>📄 JS Files List <span class="count">{{ result.js_urls|length }}</span></summary>
        <div class="details-body">
          <div class="js-list">
          {% for u in result.js_urls %}
            <div>{{ u }}</div>
          {% endfor %}
          </div>
        </div>
      </details>
      {% endif %}

      {% set any_found = false %}
      {% for group_name, keys in category_groups.items() %}
        {% set group_findings = [] %}
        {% for key in keys %}
          {% if result.all_findings.get(key) %}
            {% set _ = group_findings.append(key) %}
          {% endif %}
        {% endfor %}
        {% if group_findings %}
          {% set any_found = true %}
          <details open>
            <summary>{{ group_name }}
              <span class="count">
                {{ group_findings|map('extract_len', result.all_findings)|sum }} found
              </span>
            </summary>
            <div class="details-body">
              {% for key in group_findings %}
                {% set vals = result.all_findings[key] %}
                <div class="finding-block">
                  <h4>{{ key }} ({{ vals|length }})</h4>
                  {% for v in vals[:15] %}
                    {% set css_class = 'endpoint' if ('URL' in key or 'ENDPOINT' in key) else ('other' if key in ['EMAIL','PHONE','IP_ADDRESS','USERNAME'] else '') %}
                    <div class="finding-item {{ css_class }}">{{ v[:200] }}{% if v|length > 200 %}...{% endif %}</div>
                  {% endfor %}
                  {% if vals|length > 15 %}
                    <div class="more-note">... and {{ vals|length - 15 }} more</div>
                  {% endif %}
                </div>
              {% endfor %}
            </div>
          </details>
        {% endif %}
      {% endfor %}

      {% if result.per_file %}
      <details>
        <summary>📁 Per-File Breakdown <span class="count">{{ result.per_file|length }} files</span></summary>
        <div class="details-body">
          <table class="file-table">
            <tr><th>File</th><th>Findings</th></tr>
            {% for fname, findings in result.per_file.items() %}
              {% set total = findings.values()|map('length')|sum %}
              {% if total > 0 %}
              <tr>
                <td>{{ fname }}</td>
                <td>
                  {% for key, vals in findings.items() %}
                    {% if vals %}{{ key }}: {{ vals|length }}<br>{% endif %}
                  {% endfor %}
                </td>
              </tr>
              {% endif %}
            {% endfor %}
          </table>
        </div>
      </details>
      {% endif %}

      {% if result.functions %}
      <details>
        <summary>⚙️ Crypto Functions Code <span class="count">{{ result.functions|length }}</span></summary>
        <div class="details-body">
          {% for f in result.functions %}
            <div class="func-block">
              <div class="func-title">📄 {{ f.file }} → <b>{{ f.name }}</b></div>
              <pre>{{ f.code }}</pre>
            </div>
          {% endfor %}
        </div>
      </details>
      {% endif %}

      {% if not any_found %}
        <div class="empty-msg">✅ No sensitive patterns found in this website's JS files.</div>
      {% endif %}

      {% if scan_id %}
        <a class="download-btn" href="/download/{{ scan_id }}">⬇️ Download Full Text Report</a>
      {% endif %}
    {% endif %}
  {% endif %}

  <footer>⚠️ Sirf apni website test karo. Third-party sites pe use mat karo.</footer>
</div>
</body>
</html>
"""


@app.template_filter('extract_len')
def extract_len_filter(key, findings_dict):
    return len(findings_dict.get(key, []))


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PAGE, result=None, last_url=None,
                                   category_groups=CATEGORY_GROUPS, scan_id=None)


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template_string(HTML_PAGE, result={"error": "URL required"},
                                       last_url=None, category_groups=CATEGORY_GROUPS, scan_id=None)

    result = run_full_analysis(url)

    scan_id = str(uuid.uuid4())[:8]
    SCAN_CACHE[scan_id] = result
    # Keep cache small
    if len(SCAN_CACHE) > 50:
        oldest = list(SCAN_CACHE.keys())[0]
        SCAN_CACHE.pop(oldest, None)

    return render_template_string(HTML_PAGE, result=result, last_url=url,
                                   category_groups=CATEGORY_GROUPS, scan_id=scan_id)


@app.route("/download/<scan_id>")
def download(scan_id):
    result = SCAN_CACHE.get(scan_id)
    if not result:
        return "Report not found or expired.", 404
    text = format_text_report(result)
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=js_analysis_report_{scan_id}.txt"}
    )


@app.route("/health")
def health():
    return "OK"


# ==================== TELEGRAM BOT (ADMIN ONLY) ====================
def is_admin(user_id):
    return bool(ADMIN_IDS) and user_id in ADMIN_IDS


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
        result = run_full_analysis(url)
        report = format_text_report(result)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        return

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


def start_bot_thread():
    if BOT_TOKEN:
        t = threading.Thread(target=run_bot, daemon=True)
        t.start()


start_bot_thread()

if __name__ == "__main__":
    print(f"[+] Starting Flask web app on port {PORT}...")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
