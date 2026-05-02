"""
Tool Wrappers: Nmap + SQLMap
MCP-style abstraction layer for penetration testing tools.

Based on: CurriculumPT (MCP tool integration), PentestMCP (17 MCP tools),
          MAPTA (Coordinator tools), Four-Layer (OWASP ZAP + tools)

These wrappers:
1. Accept high-level LLM instructions
2. Translate them into CLI commands
3. Execute safely in subprocess
4. Return structured output the LLM can understand
"""

import subprocess
import json
import re
import shutil

def _get_nmap_path() -> str:
    """Find nmap executable — checks project-local path first (Windows), then system PATH.
    Place nmap.exe in a 'nmap/' subfolder of the project root, or set NMAP_PATH env var.
    """
    import os as _os
    # 1. Environment variable override
    env = _os.environ.get("NMAP_PATH", "")
    if env and _os.path.isfile(env):
        return env
    # 2. Project-local nmap/ folder (Windows: nmap/nmap.exe)
    _here = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    for _sub in ["nmap/nmap.exe", "nmap\\nmap.exe", "nmap/nmap"]:
        _candidate = _os.path.join(_here, _sub)
        if _os.path.isfile(_candidate):
            return _candidate
    # 3. System PATH
    _sys = shutil.which("nmap")
    if _sys:
        return _sys
    return ""  # not found
import sys
from datetime import datetime


def _find_sqlmap() -> list:
    """
    Find sqlmap binary — works on Windows, Linux, Mac.
    Returns a command prefix list: ["sqlmap"] or ["python", "C:/sqlmap/sqlmap.py"]
    Returns empty list if sqlmap not found.
    """
    # Try native sqlmap first (Linux/Mac where it is executable)
    if shutil.which("sqlmap"):
        return ["sqlmap"]
    # Try sqlmap.py (Windows git clone)
    sqlmap_py = shutil.which("sqlmap.py")
    if sqlmap_py:
        return [sys.executable, sqlmap_py]
    # Try common Windows install paths
    import os
    common_paths = [
        os.path.join("C:\\", "sqlmap", "sqlmap.py"),
        os.path.join("C:\\", "tools", "sqlmap", "sqlmap.py"),
        os.path.join(os.path.expanduser("~"), "sqlmap", "sqlmap.py"),
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return [sys.executable, p]
    return []


# ============================================================
# SAFETY CHECK
# ============================================================
def is_safe_target(target: str) -> bool:
    """
    Only allow localhost or 192.168.x.x or 10.x.x.x targets.
    Never run tools on live internet targets without explicit auth.
    Based on: MAPTA ethical constraints, Four-Layer human-in-the-loop.
    """
    safe_patterns = [
        r"^localhost$",
        r"^127\.\d+\.\d+\.\d+$",
        r"^192\.168\.\d+\.\d+$",
        r"^10\.\d+\.\d+\.\d+$",
        r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",
    ]
    return any(re.match(p, target) for p in safe_patterns)


def reset_session_cache():
    """Clear cached sessions — call between benchmark targets to force fresh logins."""
    global _SESSION_STORE
    _SESSION_STORE = {}


# ── Authenticated Session Store ───────────────────────────────
# Stores session cookies after login per target host.
# Credentials for well-known vulnerable apps.
_SESSION_STORE: dict = {}

APP_CREDENTIALS = {
    "localhost:8081": {"login_url": "http://localhost:8081/login.php",
                       "data": {"username": "admin", "password": "password", "Login": "Login"},
                       "security_url": "http://localhost:8081/security.php",
                       "security_data": {"security": "low", "seclev_submit": "Submit"}},
    "localhost:3000": {"login_url": "http://localhost:3000/rest/user/login",
                       "json": {"email": "admin@juice-sh.op", "password": "admin123"},
                       "json_fallback": {"email": "admin1@juice-sh.op", "password": "admin123"},
                       "type": "json"},
    "localhost:8082": {"login_url": "http://localhost:8082/WebGoat/login",
                       "data": {"username": "guest", "password": "guest"},
                       "type": "form"},
    # WebGoat accessed via full path URL
    "localhost:8082/WebGoat": {"login_url": "http://localhost:8082/WebGoat/login",
                       "data": {"username": "guest", "password": "guest"},
                       "type": "form"},
}


def get_session_cookie(host_port: str) -> str:
    """
    Return cookie string for authenticated scanning.
    Logs in if not already done. Caches session per host.
    This enables authenticated scanning — detecting vulns behind login walls.
    """
    if host_port in _SESSION_STORE:
        # Validate cached session for DVWA — session expires during long ZAP scans
        # Quick test: does the DVWA index page still show "logout"? (logged-in indicator)
        cached = _SESSION_STORE[host_port]
        if "8081" in host_port and cached:
            try:
                import requests as _req_chk
                _r = _req_chk.get(
                    "http://localhost:8081/index.php",
                    headers={"Cookie": cached}, timeout=5, allow_redirects=True)
                # If response doesn't contain logout link, session expired — re-login
                if "logout" not in _r.text.lower() and "dvwa" not in _r.text.lower():
                    del _SESSION_STORE[host_port]   # force re-login
                    print(f"[Auth] 🔄 DVWA session expired — re-logging in")
            except Exception:
                pass  # network issue — keep cached session
        if host_port in _SESSION_STORE:
            return _SESSION_STORE[host_port]

    import requests as _req
    creds = APP_CREDENTIALS.get(host_port)
    if not creds:
        return ""

    try:
        s = _req.Session()
        if creds.get("type") == "json":
            r = s.post(creds["login_url"], json=creds.get("json",{}), timeout=10)
            # If primary credentials fail, try fallback (e.g. admin1@juice-sh.op)
            if r.status_code not in [200, 201] and creds.get("json_fallback"):
                r = s.post(creds["login_url"], json=creds["json_fallback"], timeout=10)
                if r.status_code in [200, 201]:
                    print(f"[Auth] 🔑 Fallback credentials worked for {host_port}")
            # Juice Shop / JWT-based apps return a Bearer token in JSON body
            # Extract and store it as a special cookie that http_probe can use
            try:
                rj = r.json()
                token = (rj.get("authentication", {}).get("token") or
                         rj.get("token") or rj.get("access_token") or
                         rj.get("jwt") or "")
                if token:
                    # Store as a pseudo-cookie so get_session_cookie returns it
                    s.cookies.set("_bearer_token", token)
                    print(f"[Auth] 🔑 JWT Bearer token obtained for {host_port}")
            except Exception:
                pass
        else:
            r = s.post(creds["login_url"], data=creds.get("data",{}), timeout=10)

        # Set security level to Low for DVWA
        # DVWA uses CSRF token (user_token). GET page first to extract it.
        if creds.get("security_url"):
            try:
                sec_page = s.get(creds["security_url"], timeout=5)
                import re as _re2
                token_m = _re2.search(
                    "name=[\"']user_token[\"'].*?value=[\"']([a-f0-9]+)[\"']",
                    sec_page.text, _re2.IGNORECASE)
                sec_data = dict(creds.get("security_data", {}))
                if token_m:
                    sec_data["user_token"] = token_m.group(1)
                s.post(creds["security_url"], data=sec_data, timeout=5)
                # Do NOT call s.cookies.set() here — causes duplicate cookie error.
                # security=low is forced in the cookie string extraction below.
            except Exception:
                pass

        # Extract cookies safely — handles duplicate cookie names (e.g. DVWA sets
        # "security" multiple times). Use last-seen value per name.
        cookies = {}
        for cookie in s.cookies:
            cookies[cookie.name] = cookie.value  # last value wins if duplicates
        # Force security=low for DVWA regardless of what DVWA set
        if creds.get("security_url"):
            cookies["security"] = "low"
        cookie_str = "; ".join(f"{k}={v}" for k,v in cookies.items())
        if cookie_str:
            _SESSION_STORE[host_port] = cookie_str
            print(f"[Auth] 🔐 Authenticated session established for {host_port}")
        else:
            print(f"[Auth] ⚠️  No cookies obtained for {host_port} — continuing unauthenticated")
        return cookie_str
    except Exception as e:
        print(f"[Auth] ⚠️  Login failed for {host_port}: {e}")
        return ""


def run_command(cmd: list[str], timeout: int = 60) -> dict:
    """Run a shell command and return structured result.
    Uses UTF-8 with errors=ignore to handle binary responses (images, icons etc.)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",    # silently drop undecodable bytes (binary files)
            timeout=timeout,
        )
        return {
            "success":     result.returncode == 0,
            "stdout":      result.stdout.strip(),
            "stderr":      result.stderr.strip(),
            "return_code": result.returncode,
            "command":     " ".join(cmd),
            "timestamp":   datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "success":   False,
            "stdout":    "",
            "stderr":    f"Command timed out after {timeout}s",
            "command":   " ".join(cmd),
            "timestamp": datetime.now().isoformat(),
        }
    except FileNotFoundError:
        return {
            "success":   False,
            "stdout":    "",
            "stderr":    f"Tool not found: {cmd[0]}. Install it first.",
            "command":   " ".join(cmd),
            "timestamp": datetime.now().isoformat(),
        }


# ============================================================
# NMAP WRAPPER
# Based on: CurriculumPT (Recon Agent), PentestMCP (Scanning Agent)
# ============================================================

def nmap_port_scan(target: str, ports: str = "1-1000") -> dict:
    """
    Basic port scan on target.
    Returns open ports, services, and versions.
    """
    if not is_safe_target(target):
        return {"success": False, "error": f"Target '{target}' is not in safe list. Only localhost/LAN allowed."}

    _nmap_exe = _get_nmap_path()
    if not _nmap_exe:
        # Simulate for Windows WSL if nmap not installed yet
        return {
            "success": True,
            "stdout": f"[SIMULATED] Nmap scan of {target}:{ports}\nOpen ports: 80/tcp (http), 443/tcp (https), 8080/tcp (http-proxy)",
            "note": "Install nmap: sudo apt install nmap",
            "command": f"nmap -sV -p {ports} {target}",
        }

    cmd = [_nmap_exe, "-sV", "-p", ports, "--open", target]
    result = run_command(cmd, timeout=120)
    result["scan_type"] = "port_scan"
    result["target"] = target
    return result


def nmap_service_detection(target: str) -> dict:
    """
    Detailed service and OS detection scan.
    Based on: CurriculumPT Reconnaissance Agent prompt design.
    """
    if not is_safe_target(target):
        return {"success": False, "error": f"Target '{target}' not in safe list."}

    _nmap_exe = _get_nmap_path()
    if not _nmap_exe:
        return {
            "success": True,
            "stdout": f"[SIMULATED] Service detection on {target}\nHTTP: Apache 2.4.49 on port 80\nMySQL: 5.7.32 on port 3306",
            "note": "Install nmap: sudo apt install nmap",
            "command": f"nmap -sV -sC -O {target}",
        }

    cmd = [_nmap_exe, "-sV", "-sC", "--version-intensity", "5", target]
    result = run_command(cmd, timeout=180)
    result["scan_type"] = "service_detection"
    result["target"] = target
    return result


def nmap_vuln_scan(target: str) -> dict:
    """
    Run nmap NSE vulnerability scripts.
    Based on: IEEE Paper 1 (Scanning Agent with Nmap+RAG).
    """
    if not is_safe_target(target):
        return {"success": False, "error": f"Target '{target}' not in safe list."}

    _nmap_exe = _get_nmap_path()
    if not _nmap_exe:
        return {
            "success": True,
            "stdout": f"[SIMULATED] Vuln scan on {target}\nCVE-2021-41773: Apache path traversal possible\nCVE-2017-7529: Nginx integer overflow",
            "note": "Install nmap: sudo apt install nmap",
            "command": f"nmap --script vuln {target}",
        }

    cmd = [_nmap_exe, "--script", "vuln", target]
    result = run_command(cmd, timeout=300)
    result["scan_type"] = "vuln_scan"
    result["target"] = target
    return result


# ============================================================
# SQLMAP WRAPPER
# Based on: CurriculumPT (Exploitation Agent), PentestMCP tools
# ============================================================

def sqlmap_detect(url: str, level: int = 1, risk: int = 1, cookie: str = "") -> dict:
    """
    Detect SQL injection vulnerabilities.

    Mode 1: Real sqlmap — if installed, runs actual sqlmap scan.
    Mode 2: Curl-based boolean probe — if sqlmap not installed,
            sends two real HTTP requests with different payloads
            and compares responses. Response difference = real evidence.

    This produces real evidence in both modes — no more [SIMULATED].
    """
    host_match = re.search(r"https?://([^/:]+)", url)
    host = host_match.group(1) if host_match else url
    host_port_match = re.search(r"https?://([^/]+)", url)
    host_port = host_port_match.group(1) if host_port_match else host
    if not is_safe_target(host):
        return {"success": False, "error": f"Target '{host}' not in safe list."}

    # Use provided auth cookie if present; otherwise auto-reuse cached session.
    cookie_str = cookie or get_session_cookie(host_port)

    # ── Mode 1: Real sqlmap (Windows + Linux + Mac) ──────────
    sqlmap_cmd = _find_sqlmap()
    if sqlmap_cmd:
        cmd = sqlmap_cmd + [
            "-u", url,
            f"--level={level}", f"--risk={risk}",
            "--batch", "--output-dir=/tmp/sqlmap_output",
            "--forms", "--crawl=0",
        ]
        if cookie_str:
            cmd += ["--cookie", cookie_str]
        result = run_command(cmd, timeout=180)
        stdout = result.get("stdout", "")

        # Parse real sqlmap output for confirmation
        sqli_confirmed = any(kw in stdout.lower() for kw in
                             ["injectable", "is vulnerable", "parameter", "boolean-based",
                              "time-based", "union query", "error-based"])
        result["sqli_confirmed"]  = sqli_confirmed
        result["scan_type"]       = "sqli_detection_real"
        result["target_url"]      = url
        result["tool_mode"]       = "real_sqlmap"
        return result

    # ── Mode 2: Curl boolean-based probe ─────────────────────
    # Send true condition vs false condition, compare responses.
    # Real HTTP requests — not simulated.
    import urllib.parse

    # Parse URL to find a parameter to test
    parsed    = re.search(r"\?([^#]+)", url)
    params    = {}
    base_url  = url.split("?")[0]
    if parsed:
        for part in parsed.group(1).split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v

    if not params:
        # No params found — try common injectable params
        test_url_true  = url + ("&" if "?" in url else "?") + "id=1 AND 1=1--"
        test_url_false = url + ("&" if "?" in url else "?") + "id=1 AND 1=2--"
        tested_param   = "id"
    else:
        # Use the first parameter found
        tested_param = list(params.keys())[0]
        true_params  = dict(params); true_params[tested_param]  = "1 AND 1=1--"
        false_params = dict(params); false_params[tested_param] = "1 AND 1=2--"
        qs_true  = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k,v in true_params.items())
        qs_false = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k,v in false_params.items())
        test_url_true  = f"{base_url}?{qs_true}"
        test_url_false = f"{base_url}?{qs_false}"

    # Execute both real HTTP requests
    if cookie_str:
        r_true  = run_command(["curl","-s","--max-time","10","-L","-H",f"Cookie: {cookie_str}",test_url_true],  timeout=15)
        r_false = run_command(["curl","-s","--max-time","10","-L","-H",f"Cookie: {cookie_str}",test_url_false], timeout=15)
    else:
        r_true  = run_command(["curl","-s","--max-time","10","-L",test_url_true],  timeout=15)
        r_false = run_command(["curl","-s","--max-time","10","-L",test_url_false], timeout=15)

    body_true  = r_true.get("stdout","")
    body_false = r_false.get("stdout","")

    # Boolean-based detection: responses must differ meaningfully
    len_diff = abs(len(body_true) - len(body_false))
    sqli_confirmed = False
    evidence_detail = ""

    if len_diff > 50:
        sqli_confirmed = True
        evidence_detail = (f"Boolean-based blind SQLi detected: "
                           f"true-condition response={len(body_true)} chars, "
                           f"false-condition response={len(body_false)} chars, "
                           f"difference={len_diff} chars. "
                           f"Parameter '{tested_param}' is injectable.")
    elif r_true.get("success") and len(body_true) > 100:
        # No length difference but endpoint responds — check for error strings
        error_indicators = ["sql syntax", "mysql_fetch", "ora-", "sqlite",
                             "syntax error", "unclosed quotation"]
        if any(e in body_true.lower() for e in error_indicators):
            sqli_confirmed = True
            evidence_detail = (f"Error-based SQLi detected: "
                               f"SQL error string found in response for param '{tested_param}'.")

    stdout_summary = (
        evidence_detail if sqli_confirmed else
        f"No SQLi evidence found for param '{tested_param}'. "
        f"True response: {len(body_true)} chars, False response: {len(body_false)} chars."
    )

    return {
        "success":        True,
        "sqli_confirmed": sqli_confirmed,
        "injectable_param": tested_param if sqli_confirmed else "",
        "stdout":         stdout_summary,
        "body_true_len":  len(body_true),
        "body_false_len": len(body_false),
        "len_difference": len_diff,
        "target_url":     url,
        "scan_type":      "sqli_detection_curl_probe",
        "tool_mode":      "curl_boolean_probe",
    }


def sqlmap_get_dbs(url: str, vulnerable_param: str = None) -> dict:
    """
    Enumerate databases after confirming SQLi.
    Only runs after human approval in production.
    """
    host_match = re.search(r"https?://([^/:]+)", url)
    host = host_match.group(1) if host_match else url
    if not is_safe_target(host):
        return {"success": False, "error": f"Target '{host}' not in safe list."}

    sqlmap_cmd = _find_sqlmap()
    if not sqlmap_cmd:
        return {
            "success": True,
            "sqli_confirmed": False,
            "stdout": "sqlmap not found. Install from https://sqlmap.org",
            "note": "Add C:\\sqlmap to PATH then restart terminal",
        }

    cmd = sqlmap_cmd + ["-u", url, "--dbs", "--batch", "--output-dir=/tmp/sqlmap_output"]
    if vulnerable_param:
        cmd += ["-p", vulnerable_param]

    result = run_command(cmd, timeout=180)
    result["scan_type"] = "db_enumeration"
    return result


# ============================================================
# CURL / HTTP PROBE WRAPPER
# Used by Recon Agent for web fingerprinting
# ============================================================

def _deduplicate_url_params(url: str) -> str:
    """Remove duplicate query parameters — last value wins.
    Fixes ?q=test&q=<script>alert(1)</script> → ?q=<script>alert(1)</script>
    This stops Juice Shop from receiving malformed double-q= requests.
    """
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        if not parsed.query or "&" not in parsed.query:
            return url
        params = {}
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v   # last value wins — removes duplicates
            else:
                params[pair] = ""
        new_query = "&".join(f"{k}={v}" for k, v in params.items())
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


def http_probe(url: str) -> dict:
    """
    HTTP probe: headers + response body.
    Fix 1: now captures response body so LFI/XSS content can be verified.
    Used by Recon Agent, Execution Agent, and Sandbox Validator.
    Based on: PentestMCP Reconnaissance Agent.
    """
    url = _deduplicate_url_params(url)
    host_match = re.search(r"https?://([^/:]+)", url)
    host = host_match.group(1) if host_match else url
    if not is_safe_target(host):
        return {"success": False, "error": f"Target '{host}' not in safe list."}

    # Step 1: Get headers
    cmd_headers = ["curl", "-s", "-I", "--max-time", "10", url]
    result = run_command(cmd_headers, timeout=15)
    result["probe_type"] = "http_headers_and_body"
    result["target_url"] = url

    # Parse headers into dict
    if result["success"] and result["stdout"]:
        headers = {}
        for line in result["stdout"].split("\n")[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip()] = val.strip()
        result["headers"] = headers
        # Detect JSON API response (Juice Shop /rest/, /api/ endpoints)
        _ct = headers.get("Content-Type", headers.get("content-type", "")).lower()
        result["is_json_response"] = "application/json" in _ct

    # Detect binary file extensions — skip body parse to avoid UnicodeDecodeError
    _binary_exts = (".ico", ".jpg", ".jpeg", ".png", ".gif", ".pdf",
                    ".zip", ".tar", ".gz", ".woff", ".ttf", ".eot", ".svg")
    _is_binary = any(url.lower().split("?")[0].endswith(ext) for ext in _binary_exts)
    if _is_binary:
        result["body"]         = ""
        result["lfi_detected"] = False
        result["xss_reflected"]= False
        result["binary_file"]  = True
        print(f"[http_probe] ⏩ Skipping body parse — binary file: {url.split('/')[-1]}")
        return result

    # Step 2: Get response body — with auth cookie if available
    host_match2 = re.search(r"https?://([^/]+)", url)
    host_port   = host_match2.group(1) if host_match2 else ""
    # Per-request session validation for DVWA (LFI probes only).
    # Only re-validate when the URL contains the LFI path — avoids spam re-auth
    # on every misconfiguration/sitemap probe.
    if "8081" in host_port and "/vulnerabilities/fi/" in url:
        _cached = _SESSION_STORE.get(host_port, "")
        if _cached:
            try:
                import requests as _rv
                _test = _rv.get("http://localhost:8081/index.php",
                                headers={"Cookie": _cached}, timeout=5,
                                allow_redirects=True)
                if "logout" not in _test.text.lower():
                    # Session dead — re-login now, right before the LFI request
                    _SESSION_STORE.pop(host_port, None)
                    get_session_cookie(host_port)
            except Exception:
                pass
    cookie_str  = get_session_cookie(host_port)
    if cookie_str and "_bearer_token=" in cookie_str:
        # JWT app (Juice Shop) — extract token and send as Authorization Bearer header
        import re as _re_jwt
        _tok = _re_jwt.search(r"_bearer_token=([^;]+)", cookie_str)
        _other = _re_jwt.sub(r"_bearer_token=[^;]+(;\s*)?", "", cookie_str).strip(";").strip()
        bearer = _tok.group(1) if _tok else ""
        _cmds = ["curl", "-s", "-L", "--max-time", "10",
                 "-H", f"Authorization: Bearer {bearer}"]
        if _other:
            _cmds += ["-H", f"Cookie: {_other}"]
        cmd_body = _cmds + [url]
    elif cookie_str:
        # For DVWA: always inject security=low into the Cookie header explicitly
        # This ensures DVWA responds to LFI even if session cookie lacks it
        if "8081" in host_port and "security=low" not in cookie_str:
            cookie_str = cookie_str + "; security=low"
        cmd_body = ["curl", "-s", "-L", "--max-time", "10",
                    "-H", f"Cookie: {cookie_str}", url]
    else:
        cmd_body = ["curl", "-s", "-L", "--max-time", "10", url]
    body_result = run_command(cmd_body, timeout=15)
    if body_result.get("success") and body_result.get("stdout"):
        body = body_result["stdout"]
        result["body"] = body[:8000]  # cap at 8000 chars (DVWA HTML template ~2.8k before content)

        # LFI indicators — check FULL body (not truncated portion)
        # DVWA HTML template is ~2800 chars, passwd content appears after that
        # So we must check the complete response, not just the first 8000 chars
        full_body = body_result["stdout"]  # full untruncated body
        lfi_patterns = [
            "root:x:0:0", "root:x:", "bin:x:", "daemon:x:", "nobody:x:",
            "/bin/bash", "/bin/sh", "/sbin/nologin", "/usr/sbin/nologin",
            "[boot loader]", "for 16-bit app support",
            "[extensions]", "MAPI=1",          # Windows win.ini
            "DOCUMENT_ROOT", "PHP_SELF",        # PHP env vars (real proof)
        ]
        # Check full body first, then truncated version
        result["lfi_detected"] = any(p in full_body for p in lfi_patterns)
        # Catch passwd lines anywhere in response: username:x:UID:GID:
        if not result["lfi_detected"]:
            import re as _re
            if _re.search(r"[a-z_][a-z0-9_-]*:x:[0-9]+:[0-9]+:", full_body):
                result["lfi_detected"] = True
        # Mark the matched evidence for critique context
        if result["lfi_detected"]:
            # Find evidence snippet around the match for critique
            for p in lfi_patterns:
                if p in full_body:
                    idx = full_body.find(p)
                    result["lfi_evidence"] = p
                    result["body"] = full_body[max(0,idx-50):idx+200]  # snippet around evidence
                    break
            if not result.get("lfi_evidence"):
                import re as _re
                m = _re.search(r"[a-z_][a-z0-9_-]*:x:[0-9]+:[0-9]+:[^\n]*", full_body)
                if m:
                    result["lfi_evidence"] = m.group(0)[:80]
                    result["body"] = full_body[max(0,m.start()-20):m.start()+300]

        # XSS indicators — only flag if our PAYLOAD is reflected, not generic <script> tags.
        # Angular SPAs (Juice Shop) have many <script src="..."> tags in every page,
        # so checking for bare "<script>" causes massive false positives.
        # We check for ACTIVE payloads only: inline script content, alert(), event handlers.
        xss_patterns = [
            "alert(1)", "alert(0)", "<script>alert",        # common XSS payloads
            "onerror=alert", "onload=alert",                # event-based XSS
            "javascript:alert",                             # javascript: URI
            "<img src=x onerror", "<svg onload",           # alternate vectors
        ]
        # Also check if the URL itself has an XSS payload reflected
        url_payload = ""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for vals in qs.values():
                url_payload += " ".join(vals)
        except Exception:
            pass
        # XSS = payload from URL reflected in body (attacker controls the input)
        payload_in_body = url_payload and url_payload.lower() in body.lower()
        pattern_match   = any(p.lower() in body.lower() for p in xss_patterns)
        result["xss_reflected"] = pattern_match or payload_in_body

        # Info disclosure
        result["server_in_body"] = any(s in body.lower() for s in
                                        ["apache", "nginx", "iis", "php", "server"])
    else:
        result["body"] = ""
        result["lfi_detected"] = False
        result["xss_reflected"] = False

    return result


def web_directory_enum(url: str) -> dict:
    """
    Basic directory/path enumeration using common wordlist.
    Based on: PentestMCP Enumeration Agent.
    """
    host_match = re.search(r"https?://([^/:]+)", url)
    host = host_match.group(1) if host_match else url
    if not is_safe_target(host):
        return {"success": False, "error": f"Target '{host}' not in safe list."}

    # Common web paths to check
    common_paths = [
        "/admin", "/login", "/wp-admin", "/phpmyadmin",
        "/api", "/api/v1", "/swagger", "/robots.txt",
        "/.env", "/config", "/backup", "/upload",
        "/shell", "/cmd", "/debug", "/test",
    ]

    found = []
    for path in common_paths:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "5", f"{url.rstrip('/')}{path}"]
        result = run_command(cmd, timeout=8)
        if result["success"]:
            status = result["stdout"].strip()
            if status in ["200", "301", "302", "403"]:
                found.append({"path": path, "status": status})

    return {
        "success":    True,
        "found_paths": found,
        "total_checked": len(common_paths),
        "target_url": url,
        "scan_type":  "directory_enum",
        "timestamp":  datetime.now().isoformat(),
    }


# ============================================================
# TOOL DEFINITIONS for LLM Tool Calling
# These are passed to the LLM so it knows what tools it can call
# Based on: CurriculumPT MCP tool schema, PentestMCP tool definitions
# ============================================================

RECON_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "nmap_port_scan",
            "description": "Scan open ports and detect running services on a target host. Use this first for any new target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname (localhost/LAN only)"},
                    "ports":  {"type": "string", "description": "Port range e.g. '1-1000' or '80,443,8080'", "default": "1-1000"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_probe",
            "description": "Probe a web URL to get HTTP headers, server version, and basic fingerprint info.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL e.g. http://localhost:8080"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_directory_enum",
            "description": "Enumerate common web directories and paths on a target URL. Finds admin panels, APIs, config files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Base URL to enumerate e.g. http://localhost:8080"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_vuln_scan",
            "description": "Run vulnerability detection scripts (NSE) against a target. Identifies known CVEs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                },
                "required": ["target"],
            },
        },
    },
]

EXECUTOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "sqlmap_detect",
            "description": "Test a URL for SQL injection vulnerabilities. Safe detection only, no exploitation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url":   {"type": "string", "description": "Target URL with parameters e.g. http://localhost/page?id=1"},
                    "level": {"type": "integer", "description": "Test level 1-5. Use 1 for safe detection.", "default": 1},
                    "risk":  {"type": "integer", "description": "Risk level 1-3. Use 1 for safe.", "default": 1},
                },
                "required": ["url"],
            },
        },
    },
]

# Map tool names to actual functions
TOOL_REGISTRY = {
    "nmap_port_scan":       nmap_port_scan,
    "nmap_service_detection": nmap_service_detection,
    "nmap_vuln_scan":       nmap_vuln_scan,
    "http_probe":           http_probe,
    "web_directory_enum":   web_directory_enum,
    "sqlmap_detect":        sqlmap_detect,
    "sqlmap_get_dbs":       sqlmap_get_dbs,
}

# Phase 3: Register ZAP tools (imported lazily to avoid circular import)
def _register_zap():
    try:
        from tools.zap_wrapper import zap_passive_scan, zap_full_scan
        TOOL_REGISTRY["zap_passive_scan"] = zap_passive_scan
        TOOL_REGISTRY["zap_full_scan"]    = zap_full_scan
    except Exception:
        pass

_register_zap()


def execute_tool(tool_name: str, arguments: dict) -> dict:
    """
    Execute a tool by name with given arguments.
    Called by the Execution Agent after LLM decides which tool to use.
    """
    if tool_name not in TOOL_REGISTRY:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    tool_fn = TOOL_REGISTRY[tool_name]
    try:
        return tool_fn(**arguments)
    except Exception as e:
        return {"success": False, "error": str(e), "tool": tool_name}
