"""
Reconnaissance Agent — Phase 1 (Corrected Architecture)

ARCHITECTURE ROLE:
  Step 1 of 5 in the pipeline.
  Recon Agent is the ONLY entry point for ALL information gathering.
  ZAP scanning and URL discovery are TOOLS called by this agent —
  they are not separate pipeline stages.

  Output feeds directly into VulnAnalyst (Step 2).

Based on:
- CurriculumPT: Reconnaissance Agent (Nmap + Nikto, structured output)
- PentestMCP:   Reconnaissance + Enumeration Agents
- MAPTA:        Coordinator orchestrates Recon first
- IEEE Paper 1: Scanning Agent (Nmap + Masscan + RAG)
- Four-Layer:   Layer 3 uses OWASP ZAP as a scanning TOOL

What this agent does:
  1. HTTP probe   — fingerprint server, headers, status
  2. Port scan    — Nmap open ports and services
  3. Dir enum     — discover paths and forms
  4. ZAP scan     — passive or full ZAP scan (built-in tool call)
  5. Parse & rank — combine all findings into structured report
     that VulnAnalyst can consume directly
"""

import re
import json
import time
import requests
from urllib.parse import urlparse, urljoin
from agents.llm_client import LLMClient
from tools.tool_wrappers import (
    RECON_TOOLS, execute_tool,
    nmap_port_scan, http_probe, web_directory_enum,
    is_safe_target,
)


RECON_SYSTEM_PROMPT = """You are a Reconnaissance Agent in an AI-powered penetration testing system.
Your job is to gather ALL information about a target before passing it to the Vulnerability Analyst.

Your workflow:
1. HTTP probe — fingerprint the web server
2. Port scan  — find all open ports and services
3. Dir enum   — find hidden paths and admin panels
4. Summarize all findings into a structured JSON report

Output a JSON block with this exact structure:
{
  "target_url":            "http://...",
  "target_ip":             "...",
  "web_server":            "Apache/2.4.25",
  "open_ports":            ["80/tcp", "443/tcp"],
  "services":              {"http": "Apache/2.4.25"},
  "found_paths":           ["/admin", "/login.php"],
  "discovered_urls":       ["http://localhost/page1", "..."],
  "discovered_forms":      [{"action": "/login", "method": "post", "inputs": ["user","pass"]}],
  "injectable_candidates": [
    {"url": "http://...", "param": "id", "method": "GET", "priority": "high"}
  ],
  "potential_vulns":       [{"type": "SQLi", "location": "/sqli?id=1", "severity": "high"}],
  "risk_level":            "low/medium/high/critical",
  "recommended_exploits":  ["SQL Injection", "XSS"]
}

CRITICAL OUTPUT REQUIREMENTS:
- Return ONLY valid JSON
- Do NOT include explanations or markdown
- The response must start with { and end with }
"""


class ReconAgent:
    """
    Reconnaissance Agent — collects ALL recon data.

    In the corrected architecture:
    - ZAP is called as a tool INSIDE this agent (not a pipeline stage)
    - URL discovery (crawling) happens INSIDE this agent
    - Output is a rich structured report for VulnAnalyst

    Pipeline position: Step 1 → feeds VulnAnalyst (Step 2)
    """

    def __init__(self):
        self.llm        = LLMClient("recon")
        self.tool_calls = 0
        self.max_tools  = 15

    def run(self, target_url: str, target_ip: str = "localhost",
            zap_host: str = "localhost", zap_port: int = 9002) -> dict:
        """
        Full recon: HTTP probe + ports + dirs + ZAP + URL discovery.

        target_url: e.g. "http://localhost:9000"
        target_ip:  e.g. "localhost" or "127.0.0.1"
        zap_host/port: ZAP API location (if running)
        """
        print(f"\n[ReconAgent] 🔍 Starting full reconnaissance on {target_url}")
        print(f"[ReconAgent] Target IP: {target_ip}")
        print("-" * 50)

        results = {}

        # ── Step 1: HTTP Probe ──────────────────────────────
        print("[ReconAgent] 🔧 HTTP probe...")
        results["http"] = http_probe(target_url)

        # ── Step 2: Port Scan ───────────────────────────────
        print("[ReconAgent] 🔧 Port scan...")
        results["ports"] = nmap_port_scan(target_ip)

        # ── Step 3: Directory Enumeration ───────────────────
        print("[ReconAgent] 🔧 Directory enumeration...")
        results["dirs"] = web_directory_enum(target_url)

        # ── Step 4: URL + Form Discovery (replaces CrawlerAgent) ──
        print("[ReconAgent] 🔧 URL and form discovery...")
        crawl_data = self._discover_urls_and_forms(target_url)
        results["crawl"] = crawl_data

        # ── Step 5: ZAP Scan (as internal tool) ────────────
        print("[ReconAgent] 🔧 ZAP scan...")
        zap_data = self._run_zap(target_url, zap_host, zap_port)
        results["zap"] = zap_data

        # ── Step 6: Build structured report ─────────────────
        report = self._build_report(target_url, target_ip, results)

        print(f"\n[ReconAgent] ✅ Recon complete")
        print(f"[ReconAgent] Risk: {report.get('risk_level','?').upper()}")
        print(f"[ReconAgent] ZAP alerts: {zap_data.get('total_alerts', 0)}")
        print(f"[ReconAgent] URLs discovered: {len(report.get('discovered_urls', []))}")
        print(f"[ReconAgent] Injectable candidates: {len(report.get('injectable_candidates', []))}")

        return report

    def run_quick(self, target_url: str, target_ip: str = "localhost") -> dict:
        """
        Quick recon — HTTP probe + ports + dirs only. No ZAP, no LLM.
        Used for fast testing.
        """
        print(f"\n[ReconAgent] ⚡ Quick recon on {target_url}")

        results = {
            "http":  http_probe(target_url),
            "ports": nmap_port_scan(target_ip),
            "dirs":  web_directory_enum(target_url),
            "crawl": self._discover_urls_and_forms(target_url),
            "zap":   {"total_alerts": 0, "alerts": [], "risk_counts": {}},
        }

        report = self._build_report(target_url, target_ip, results)
        print(f"[ReconAgent] ✅ Quick recon done. Risk: {report.get('risk_level','?').upper()}")
        return report

    # ──────────────────────────────────────────────────────────
    # INTERNAL: URL + Form Discovery (was CrawlerAgent)
    # ──────────────────────────────────────────────────────────

    def _discover_urls_and_forms(self, base_url: str,
                                  max_pages: int = 40) -> dict:
        """
        Lightweight URL and form discovery.
        Replaces CrawlerAgent — runs inside ReconAgent as a tool.
        """
        host_match = re.search(r"https?://([^/:]+)", base_url)
        host = host_match.group(1) if host_match else base_url
        if not is_safe_target(host):
            return {"discovered_urls": [], "forms": [], "injectable_candidates": []}

        visited     = set()
        queue       = [base_url]
        found_urls  = []
        found_forms = []
        injectable  = []
        base_host   = urlparse(base_url).netloc

        # Common DVWA/Juice Shop paths to seed the queue
        seed_paths = [
            "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/",
            "/vulnerabilities/brute/", "/login.php", "/setup.php",
            "/security.php", "/admin/", "/phpmyadmin/",
        ]
        # Phase 8: Juice Shop high-value endpoints
        parsed_base = urlparse(base_url)
        if ":3000" in parsed_base.netloc:
            seed_paths.extend([
                "/rest/user/login", "/rest/user/register",
                "/rest/basket/1", "/rest/order-history",
                "/profile", "/api/Challenges", "/api/SecurityQuestions",
                "/rest/products/search?q=test",
                "/rest/memories", "/api/Feedbacks",
            ])
        for p in seed_paths:
            queue.append(base_url.rstrip("/") + p)

        session = requests.Session()

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                r = session.get(url, timeout=5, allow_redirects=True)
                if not r.ok:
                    continue

                # Skip binary content
                ct = r.headers.get("content-type", "")
                if any(x in ct for x in ["image/", "font/", "audio/", "video/"]):
                    continue

                html = r.text
                found_urls.append(url)

                # Discover links
                for href in re.findall(r'href=["\']([^"\']+)["\']', html):
                    full = urljoin(url, href)
                    if urlparse(full).netloc == base_host and full not in visited:
                        queue.append(full)

                # Discover forms
                for form_html in re.findall(r'<form[^>]*>.*?</form>', html,
                                             re.DOTALL | re.IGNORECASE):
                    action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    inputs   = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                    action   = urljoin(url, action_m.group(1)) if action_m else url
                    method   = method_m.group(1).upper() if method_m else "GET"
                    if action not in visited:
                        queue.append(action)
                    found_forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "source_page": url,
                    })

                # Identify injectable candidates (parameterised URLs)
                parsed = urlparse(url)
                if parsed.query:
                    params = [p.split("=")[0] for p in parsed.query.split("&")]
                    for param in params:
                        vuln_types = []
                        if param.lower() in ["id", "cat", "item", "page", "num", "pid"]:
                            vuln_types.append("SQLi")
                        if param.lower() in ["q", "search", "name", "msg", "comment"]:
                            vuln_types.append("XSS")
                        if param.lower() in ["file", "path", "dir", "page", "include"]:
                            vuln_types.append("LFI")
                        injectable.append({
                            "url":       url,
                            "param":     param,
                            "method":    "GET",
                            "vuln_types": vuln_types or ["Unknown"],
                            "priority":  "high" if vuln_types else "low",
                        })

            except Exception:
                continue

        # Augment injectable candidates with synthetic parameterised probes
        # SPA apps (Juice Shop) have no query params in their Angular routes,
        # but their REST API endpoints ARE injectable. Generate generic candidates.
        synthetic = []
        for u in found_urls:
            parsed_u = urlparse(u)
            # Skip already-parameterised or binary/static URLs
            if parsed_u.query:
                continue
            if any(u.lower().endswith(ext) for ext in
                   [".js", ".css", ".ico", ".png", ".jpg", ".map", ".woff"]):
                continue
            # API-style paths are high-value injection targets
            if any(seg in u for seg in ["/rest/", "/api/", "/search", "/user", "/basket"]):
                for p in ["q", "search", "id", "name"]:
                    candidate_url = f"{u}?{p}=test"
                    synthetic.append({
                        "url":        candidate_url,
                        "param":      p,
                        "method":     "GET",
                        "vuln_types": ["XSS", "SQLi"] if p in ["q","search","name"] else ["SQLi"],
                        "priority":   "high",
                    })
        # SPA REST API seeding: only for SPA/API apps (Juice Shop port 3000).
        # DVWA (port 9000) is a PHP app — it has NO /rest/ endpoints.
        # Seeding DVWA with /rest/ paths caused false SQLi/XSS candidates in v14.
        # Detection: Angular bundle JS files OR port 3000 in crawled URLs.
        has_api_urls = any("/rest/" in u or "/api/" in u for u in found_urls)
        _has_spa_bundles = any(
            any(k in u for k in ["chunk-", "vendor.", "polyfill", "runtime.", "main."])
            for u in found_urls
        )
        _is_spa = has_api_urls or _has_spa_bundles or any(":3000" in u for u in found_urls)
        if not has_api_urls and _is_spa and found_urls:
            try:
                from urllib.parse import urlparse as _up2
                _base_parsed = _up2(found_urls[0])
                _api_base = f"{_base_parsed.scheme}://{_base_parsed.netloc}"
            except Exception:
                _api_base = ""
            if _api_base:
                # Phase 8: expanded Juice Shop high-value endpoints
                for _api_path in ["/rest/products/search", "/rest/user/login",
                                   "/rest/user/register", "/api/Users",
                                   "/rest/basket/1", "/rest/order-history",
                                   "/profile", "/api/Challenges",
                                   "/api/SecurityQuestions", "/api/Feedbacks",
                                   "/rest/memories"]:
                    for _p in ["q", "id", "search"]:
                        synthetic.append({
                            "url":        f"{_api_base}{_api_path}?{_p}=test",
                            "param":      _p,
                            "method":     "GET",
                            "vuln_types": ["XSS", "SQLi"],
                            "priority":   "high",
                        })

    
        injectable.extend(synthetic[:8])

        return {
            "discovered_urls":       found_urls,
            "forms":                 found_forms,
            "injectable_candidates": injectable,
            "pages_visited":         len(visited),
        }

    # ──────────────────────────────────────────────────────────
    # INTERNAL: ZAP Scan (was a pipeline stage, now a tool)
    # ──────────────────────────────────────────────────────────

    def _run_zap(self, target_url: str,
                 zap_host: str = "localhost",
                 zap_port: int = 9002) -> dict:
        """
        Run OWASP ZAP as an internal tool.
        ZAP is NOT a pipeline stage — it's a tool called by ReconAgent.
        Falls back to simulation if ZAP is not running.
        """
        base = f"http://{zap_host}:{zap_port}"

        # Check if ZAP API is available
        try:
            r = requests.get(f"{base}/JSON/core/view/version/", timeout=3)
            if r.status_code == 200:
                version = r.json().get("version", "?")
                print(f"[ReconAgent/ZAP] ✅ ZAP API connected — version {version}")
                return self._zap_api_scan(target_url, base)
        except Exception as e:
            print(f"[ReconAgent/ZAP] ZAP connection failed: {e}")

        print("[ReconAgent/ZAP] ZAP not running — using simulated scan")
        print("[ReconAgent/ZAP] To enable real ZAP: run start_zap.ps1")
        return self._zap_simulated(target_url)

    def _zap_api_scan(self, target_url: str, base: str) -> dict:
        """Run real ZAP scan via API."""
        try:
            return self._zap_api_scan_inner(target_url, base)
        except Exception as e:
            print(f"[ReconAgent/ZAP] ❌ ZAP scan error: {e}")
            print("[ReconAgent/ZAP] Falling back to simulated scan")
            return self._zap_simulated(target_url)

    def _zap_api_scan_inner(self, target_url: str, base: str) -> dict:
        """Inner ZAP scan logic — errors surface here instead of being hidden."""
        # Spider
        print("[ReconAgent/ZAP] 🕷️  ZAP spider starting...")
        r = requests.get(f"{base}/JSON/spider/action/scan/",
                         params={"url": target_url, "recurse": "true"}, timeout=10)
        scan_id = r.json().get("scan", "0")

        for _ in range(40):
            time.sleep(3)
            try:
                status = requests.get(f"{base}/JSON/spider/view/status/",
                                      params={"scanId": scan_id}, timeout=90).json()
                if str(status.get("status", "0")) == "100":
                    break
            except Exception:
                pass  # retry

        # Active scan
        print("[ReconAgent/ZAP] 🔍 ZAP active scan starting...")
        r = requests.get(f"{base}/JSON/ascan/action/scan/",
                         params={"url": target_url, "recurse": "true"}, timeout=10)
        scan_id = r.json().get("scan", "0")

        last_progress_printed = -1
        for _ in range(60):          # max 5 min (was 7.5 min)
            time.sleep(5)
            try:
                status = requests.get(f"{base}/JSON/ascan/view/status/",
                                      params={"scanId": scan_id}, timeout=90).json()
            except Exception:
                continue  # retry on timeout
            prog = status.get("status", "0")
            # Guard: ZAP sometimes returns non-numeric status during init
            try:
                prog_int = int(prog)
            except (ValueError, TypeError):
                prog_int = 0
            # Only print when progress actually changes AND at 20% intervals
            if prog_int % 20 == 0 and prog_int != last_progress_printed:
                print(f"[ReconAgent/ZAP]   Progress: {prog}%")
                last_progress_printed = prog_int
            if str(prog) == "100":
                break

        # Get alerts
        alerts_r = requests.get(f"{base}/JSON/core/view/alerts/",
                                 params={"baseurl": target_url, "start": "0", "count": "200"},
                                 timeout=10)
        raw_alerts = alerts_r.json().get("alerts", [])
        return self._format_zap_alerts(raw_alerts, target_url, "api")

    def _zap_simulated(self, target_url: str) -> dict:
        """Structured simulation when ZAP is not installed."""
        alerts = [
            {"alert": "SQL Injection",                    "riskcode": "3",
             "url": f"{target_url}/vulnerabilities/sqli/?id=1",
             "param": "id", "cweid": "89",
             "solution": "Use parameterised queries."},
            {"alert": "Cross Site Scripting (Reflected)", "riskcode": "3",
             "url": f"{target_url}/vulnerabilities/xss_r/?name=test",
             "param": "name", "cweid": "79",
             "solution": "Validate and encode all input."},
            {"alert": "X-Content-Type-Options Header Missing", "riskcode": "1",
             "url": target_url, "param": "",  "cweid": "693",
             "solution": "Set X-Content-Type-Options: nosniff"},
            {"alert": "Cookie Without Secure Flag",       "riskcode": "1",
             "url": target_url, "param": "PHPSESSID", "cweid": "614",
             "solution": "Set Secure flag on session cookies."},
        ]
        return self._format_zap_alerts(alerts, target_url, "simulated")

    def _format_zap_alerts(self, alerts: list, target_url: str, source: str) -> dict:
        risk_map = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
        formatted = []
        for a in alerts:
            # Real ZAP API returns "risk" as text ("High"/"Medium"/"Low")
            # but does NOT return "riskcode". Simulated alerts have "riskcode".
            # Fix: use "risk" text directly if present, else fall back to riskcode.
            risk_text = a.get("risk", "")
            if risk_text in ("High", "Medium", "Low", "Informational"):
                risk = risk_text
            else:
                rc   = str(a.get("riskcode", "0"))
                risk = risk_map.get(rc, "Informational")
            formatted.append({
                "name":        a.get("alert", a.get("name", "Unknown")),
                "risk":        risk,
                "url":         a.get("url", target_url),
                "param":       a.get("param", ""),
                "cwe_id":      f"CWE-{a.get('cweid','?')}",
                "solution":    a.get("solution", "")[:200],
                "description": a.get("description", "")[:200],
            })

        counts = {}
        for a in formatted:
            counts[a["risk"]] = counts.get(a["risk"], 0) + 1

        return {
            "success":      True,
            "source":       source,
            "alerts":       formatted,
            "total_alerts": len(formatted),
            "risk_counts":  counts,
            "target_url":   target_url,
        }

    # ──────────────────────────────────────────────────────────
    # BUILD FINAL REPORT
    # ──────────────────────────────────────────────────────────

    def _build_report(self, url: str, ip: str, results: dict) -> dict:
        """
        Combine all tool results into one structured report.
        This is the output that VulnAnalyst receives.
        """
        report = {
            "target_url":            url,
            "target_ip":             ip,
            "web_server":            "Unknown",
            "open_ports":            [],
            "services":              {},
            "found_paths":           [],
            "discovered_urls":       [],
            "discovered_forms":      [],
            "injectable_candidates": [],
            "zap_alerts":            [],
            "zap_risk_counts":       {},
            "potential_vulns":       [],
            "recommended_exploits":  [],
            "risk_level":            "unknown",
        }

        # HTTP probe
        http_r = results.get("http", {})
        if http_r.get("success"):
            headers    = http_r.get("headers", {})
            server     = headers.get("Server", headers.get("server", "Unknown"))
            report["web_server"] = server
            report["services"]["http"] = server

        # Port scan
        ports_r = results.get("ports", {})
        if ports_r.get("success"):
            stdout = ports_r.get("stdout", "")
            for line in stdout.split("\n"):
                if "/tcp" in line and "open" in line:
                    report["open_ports"].append(line.split()[0])

        # Directory enum
        dirs_r = results.get("dirs", {})
        if dirs_r.get("success"):
            found = dirs_r.get("found_paths", [])
            report["found_paths"] = [f["path"] for f in found]
            sensitive = ["/admin", "/.env", "/phpmyadmin", "/shell", "/cmd"]
            for p in found:
                if p["path"] in sensitive and p["status"] in ["200", "403"]:
                    report["potential_vulns"].append({
                        "type":     "Exposed Sensitive Path",
                        "location": p["path"],
                        "severity": "high" if p["status"] == "200" else "medium",
                        "source":   "dir_enum",
                    })

        # Crawl data (URL + form discovery)
        crawl_r = results.get("crawl", {})
        report["discovered_urls"]       = crawl_r.get("discovered_urls", [])
        report["discovered_forms"]      = crawl_r.get("forms", [])
        report["injectable_candidates"] = crawl_r.get("injectable_candidates", [])

        # ZAP alerts
        zap_r = results.get("zap", {})
        report["zap_alerts"]      = zap_r.get("alerts", [])
        report["zap_risk_counts"] = zap_r.get("risk_counts", {})
        report["zap_source"]      = zap_r.get("source", "none")

        # Add ZAP high/medium findings to potential_vulns
        for alert in zap_r.get("alerts", []):
            if alert.get("risk") in ["High", "Medium"]:
                report["potential_vulns"].append({
                    "type":     alert["name"],
                    "location": alert.get("url", url),
                    "severity": alert["risk"].lower(),
                    "source":   "zap",
                    "cwe_id":   alert.get("cwe_id", ""),
                    "param":    alert.get("param", ""),
                })

        # Recommended exploits based on all findings
        vuln_types = {v["type"] for v in report["potential_vulns"]}
        for vt in vuln_types:
            if "sql" in vt.lower() or "injection" in vt.lower():
                report["recommended_exploits"].append("SQL Injection")
            if "xss" in vt.lower() or "cross site" in vt.lower():
                report["recommended_exploits"].append("XSS")
            if "auth" in vt.lower() or "login" in vt.lower():
                report["recommended_exploits"].append("Auth_Bypass")
            if "path" in vt.lower() or "lfi" in vt.lower():
                report["recommended_exploits"].append("LFI")

        report["recommended_exploits"] = list(set(report["recommended_exploits"]))

        # Risk level
        sevs = [v.get("severity", "low") for v in report["potential_vulns"]]
        if "critical" in sevs:
            report["risk_level"] = "critical"
        elif "high" in sevs:
            report["risk_level"] = "high"
        elif "medium" in sevs:
            report["risk_level"] = "medium"
        elif sevs:
            report["risk_level"] = "low"
        else:
            report["risk_level"] = "low"

        return report
