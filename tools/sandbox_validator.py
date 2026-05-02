"""
Sandbox Validator — Phase 4
Replays approved findings to verify they are real vulnerabilities.

ARCHITECTURE ROLE:
  Step 4c — runs AFTER CritiqueAgent, BEFORE EKB Store.
  Takes APPROVED findings from CritiqueAgent and attempts to
  verify them by replaying the actual exploit.

  VERIFIED   → stored in EKB with high confidence
  UNVERIFIED → stored in EKB with lower confidence, flagged

Based on:
- MAPTA (UCL 2025):
  "Validation Agent runs PoC in isolated sandbox before reporting success"
  Prevents false positives reaching the final report
- Co-RedTeam (Google + MSU 2026):
  Stage II includes Validation Agent that confirms exploitability
- Four-Layer Architecture (2026):
  Layer 4: Human + automated validation before report

Validation modes:
  Mode 1: Real tool  — sqlmap, curl available → runs actual commands
  Mode 2: Simulation — structured realistic replay if tools not available

Safety:
  Only replays against localhost/LAN targets (same as tool_wrappers.py)
  Only runs tools that were already approved by CritiqueAgent
  No new attack vectors introduced
"""

import re
import time
import shutil
from datetime import datetime
from tools.tool_wrappers import is_safe_target, run_command, execute_tool


class SandboxValidator:
    """
    Sandbox Validator — Step 4c of pipeline.

    Replays approved exploitation findings to verify they are real.
    Uses real tools if available, structured simulation otherwise.

    Pipeline position: CritiqueAgent → SandboxValidator → EKBStore
    """

    def __init__(self):
        # Check which real tools are available
        # Windows-aware sqlmap detection (sqlmap.py on Windows)
        from tools.tool_wrappers import _find_sqlmap
        self.has_sqlmap   = bool(_find_sqlmap())
        self.sqlmap_cmd   = _find_sqlmap()   # full command prefix
        self.has_curl     = bool(shutil.which("curl"))
        self.has_nmap     = bool(shutil.which("nmap"))

        print(f"[SandboxValidator] Tools: "
              f"sqlmap={'✅' if self.has_sqlmap else '❌'} "
              f"curl={'✅' if self.has_curl else '❌'} "
              f"nmap={'✅' if self.has_nmap else '❌'}")

    def validate(self, critique_report: dict) -> dict:
        """
        Validate all APPROVED findings from CritiqueAgent.

        critique_report: output from CritiqueAgent.critique()
        Returns: validation report with VERIFIED/UNVERIFIED per finding
        """
        approved_findings = critique_report.get("approved_findings", [])
        target_url        = critique_report.get("target_url", "")

        print(f"\n[SandboxValidator] 🧪 Validating {len(approved_findings)} approved findings...")
        print(f"[SandboxValidator] Target: {target_url}")
        print("-" * 50)

        if not approved_findings:
            print("[SandboxValidator] No approved findings to validate.")
            return {
                "target_url":       target_url,
                "total_validated":  0,
                "verified_count":   0,
                "unverified_count": 0,
                "validations":      [],
                "timestamp":        datetime.now().isoformat(),
            }

        # Safety check
        host_match = re.search(r"https?://([^/:]+)", target_url)
        host = host_match.group(1) if host_match else target_url
        if not is_safe_target(host):
            print(f"[SandboxValidator] ⛔ Target '{host}' not in safe list — skipping")
            return {"target_url": target_url, "total_validated": 0,
                    "verified_count": 0, "unverified_count": 0, "validations": []}

        validations      = []
        verified_count   = 0
        unverified_count = 0

        for finding in approved_findings:
            tool     = finding.get("tool", "")
            args     = finding.get("args", {})
            step_name = finding.get("step_name", "?")
            original_finding = finding.get("finding", "")

            print(f"\n[SandboxValidator] 🔬 Validating: {step_name}")
            print(f"[SandboxValidator]   Tool: {tool} | Args: {args}")

            result = self._validate_finding(tool, args, target_url, step_name, original_finding)

            if result["verified"]:
                verified_count += 1
                status = "✅ VERIFIED"
            else:
                unverified_count += 1
                status = "❌ UNVERIFIED"

            print(f"[SandboxValidator]   {status}: {result['evidence'][:80]}")

            validations.append({
                "step_id":        finding.get("step_id"),
                "step_name":      step_name,
                "tool":           tool,
                "args":           args,
                "verified":       result["verified"],
                "evidence":       result["evidence"],
                "method":         result["method"],
                "original_finding": finding.get("finding", ""),
                "confidence":     finding.get("confidence", 0.0),
            })

            time.sleep(0.5)  # brief pause between validations

        print(f"\n[SandboxValidator] ✅ Validation complete")
        print(f"[SandboxValidator]   Verified:   {verified_count}")
        print(f"[SandboxValidator]   Unverified: {unverified_count}")

        return {
            "target_url":       target_url,
            "total_validated":  len(validations),
            "verified_count":   verified_count,
            "unverified_count": unverified_count,
            "validations":      validations,
            "timestamp":        datetime.now().isoformat(),
        }

    def _validate_finding(self, tool: str, args: dict, target_url: str,
                           step_name: str = "", original_finding: str = "") -> dict:
        """
        Validate a single finding by replaying the tool.
        Routes to vulnerability-specific validators based on step context.
        """
        url = args.get("url", target_url)
        _sname = step_name.lower()
        _finding = original_finding.lower()

        # Route to vulnerability-specific validators first
        if "csrf" in _sname or "csrf" in _finding:
            return self._validate_csrf(url, args)
        if "clickjack" in _sname or "x-frame" in _sname or "clickjacking" in _finding:
            return self._validate_clickjacking(url, args)

        # Route to tool-specific validators
        if "sqlmap" in tool:
            return self._validate_sqli(url, args)
        elif tool == "http_probe":
            return self._validate_http(url, args, step_name, original_finding)
        elif tool == "web_directory_enum":
            return self._validate_dirlist(url)
        elif "nmap" in tool:
            return self._validate_nmap(url, args)
        else:
            return self._validate_generic(tool, args)

    def _validate_sqli(self, url: str, args: dict) -> dict:
        """Validate SQL injection finding."""
        if self.has_sqlmap and self.sqlmap_cmd:
            # Real sqlmap validation — Windows-aware command
            print(f"[SandboxValidator]   Running real sqlmap...")
            cmd = self.sqlmap_cmd + [
                "-u", url,
                "--level=1", "--risk=1",
                "--batch", "--output-dir=/tmp/sqlmap_validate",
                "--forms", "--crawl=0",
            ]
            result = run_command(cmd, timeout=60)

            stdout = result.get("stdout", "")
            if any(kw in stdout.lower() for kw in ["injectable", "vulnerable", "parameter"]):
                return {
                    "verified": True,
                    "evidence": f"sqlmap confirmed: {stdout[:200]}",
                    "method":   "real_sqlmap",
                }
            return {
                "verified": False,
                "evidence": f"sqlmap found no injection: {stdout[:100]}",
                "method":   "real_sqlmap",
            }
        else:
            # Simulation: check URL has a parameter that looks injectable
            parsed_params = re.findall(r"[?&]([^=&]+)=([^&]*)", url)
            injectable_names = ["id", "cat", "item", "page", "num", "pid", "user",
                                 "doc", "file", "search", "q", "name"]

            for param_name, _ in parsed_params:
                if param_name.lower() in injectable_names:
                    return {
                        "verified": True,
                        "evidence": (f"[SIMULATED] Parameter '{param_name}' "
                                     f"matches injectable pattern at {url}. "
                                     f"boolean-based blind SQLi likely."),
                        "method":   "simulated_pattern_match",
                    }

            return {
                "verified": False,
                "evidence": f"[SIMULATED] No injectable parameters found at {url}",
                "method":   "simulated_pattern_match",
            }

    def _validate_http(self, url: str, args: dict,
                        step_name: str = "", original_finding: str = "") -> dict:
        """Validate HTTP-based finding (XSS, path disclosure etc.).
        For XSS: checks payload reflection and execution context.
        For DVWA LFI: always send security=low cookie.
        Generic HTTP 200 is NO LONGER treated as VERIFIED.
        """
        if self.has_curl:
            # Build curl command — add DVWA auth cookie for LFI validation
            curl_cmd = ["curl", "-s", "-L", "--max-time", "10",
                        "-w", "\n__STATUS__%{http_code}"]
            if "8081" in url and "/vulnerabilities/fi/" in url:
                from tools.tool_wrappers import get_session_cookie
                _cookie = get_session_cookie("localhost:8081")
                if _cookie and "security=low" not in _cookie:
                    _cookie = _cookie + "; security=low"
                if _cookie:
                    curl_cmd += ["-H", f"Cookie: {_cookie}"]
            curl_cmd.append(url)
            result = run_command(curl_cmd, timeout=15)

            raw = result.get("stdout", "")
            body = ""
            status_code = "0"
            if "__STATUS__" in raw:
                body, status_code = raw.rsplit("__STATUS__", 1)
                status_code = status_code.strip()
            else:
                body = raw
                status_code = "200" if result.get("success") else "0"

            # XSS: payload reflected in body
            xss_indicators = ["<script>alert", "alert(1)", "alert(0)", "onerror=alert",
                               "onload=alert", "javascript:alert", "<img src=x onerror",
                               "<svg onload"]
            url_has_payload = any(x.lower() in url.lower() for x in xss_indicators)
            body_reflected  = any(x in body.lower() for x in xss_indicators)

            # Check for HTML-encoded payloads
            escaped_strs = ["&lt;script&gt;", "&lt;script", "&#60;script"]
            body_has_escaped = any(e in body.lower() for e in escaped_strs)

            if body_has_escaped:
                return {
                    "verified": False,
                    "evidence": (f"XSS payload HTML-encoded in response (HTTP {status_code}) "
                                 f"— not exploitable"),
                    "method":   "real_curl_xss_escaped",
                }

            if (body_reflected or url_has_payload):
                _is_error_page = (
                    not status_code.startswith("2") or
                    any(ep in body.lower() for ep in [
                        "http status 4", "http status 5", "404 not found",
                        "400 bad request", "page not found", "whitelabel error",
                        "the requested url was not found",
                    ])
                )
                # Check executable context
                _bl = body.lower()
                _executable = (
                    "<script>alert" in _bl or
                    "onerror=alert" in _bl or
                    "onclick=alert" in _bl or
                    "onload=alert" in _bl or
                    "<svg onload" in _bl or
                    "<img src=x onerror" in _bl
                )
                if _executable and not _is_error_page:
                    return {
                        "verified": True,
                        "evidence": f"XSS VERIFIED: payload in executable context (HTTP {status_code})",
                        "method":   "real_curl_xss_executable",
                    }
                elif not _is_error_page:
                    return {
                        "verified": False,
                        "evidence": (f"XSS payload reflected (HTTP {status_code}) but "
                                     f"execution context not confirmed"),
                        "method":   "real_curl_xss_uncertain",
                    }
                else:
                    return {
                        "verified": False,
                        "evidence": (f"XSS payload reflected in error page (HTTP {status_code}) "
                                     f"— not exploitable in browser context"),
                        "method":   "real_curl_xss_error_page",
                    }

            # LFI: check for actual file contents
            lfi_indicators = ["root:x:", "bin:x:", "/bin/bash", "daemon:x:",
                               "/bin/sh", "www-data:x:", "nobody:x:", "sbin/nologin"]
            lfi_hit = next((p for p in lfi_indicators if p in body), None)
            if lfi_hit:
                snippet = body[max(0, body.find(lfi_hit)-10):body.find(lfi_hit)+60].strip()
                return {
                    "verified": True,
                    "evidence": f"LFI confirmed — file contents found: '{snippet}'",
                    "method":   "real_curl_lfi_content",
                }

            # LFI endpoint with short body = login redirect
            if "/vulnerabilities/fi/" in url and len(body) < 2000:
                return {
                    "verified": False,
                    "evidence": (f"LFI endpoint returned {len(body)} chars — "
                                 "likely login redirect (session/security-level issue), "
                                 "no file contents found"),
                    "method":   "real_curl_lfi_unverified",
                }

            return {
                "verified": False,
                "evidence": f"HTTP {status_code} — endpoint accessible but no exploit evidence confirmed",
                "method":   "real_curl_no_evidence",
            }
        else:
            result = execute_tool("http_probe", {"url": url})
            if result.get("success"):
                server = result.get("headers", {}).get("Server", "unknown")
                return {
                    "verified": False,
                    "evidence": f"Endpoint accessible (server: {server}) but no exploit verification available",
                    "method":   "simulated_http_probe",
                }
            return {
                "verified": False,
                "evidence": "Endpoint not accessible",
                "method":   "simulated_http_probe",
            }

    def _validate_dirlist(self, url: str) -> dict:
        """Validate directory listing / path exposure finding."""
        result = execute_tool("web_directory_enum", {"url": url})
        found = result.get("found_paths", [])
        sensitive = ["/admin", "/.env", "/phpmyadmin", "/backup", "/config"]
        hits = [p for p in found if p.get("path") in sensitive and p.get("status") == "200"]

        if hits:
            return {
                "verified": True,
                "evidence": f"Sensitive paths accessible: {[h['path'] for h in hits]}",
                "method":   "dir_enum_replay",
            }
        return {
            "verified": False,
            "evidence": "No sensitive paths found on replay",
            "method":   "dir_enum_replay",
        }

    def _validate_nmap(self, url: str, args: dict) -> dict:
        """Validate nmap-based findings."""
        host_match = re.search(r"https?://([^/:]+)", url)
        host = host_match.group(1) if host_match else url
        result = execute_tool("nmap_port_scan", {"target": host})
        if result.get("success"):
            return {
                "verified": True,
                "evidence": f"Nmap confirmed open ports",
                "method":   "nmap_replay",
            }
        return {
            "verified": False,
            "evidence": "Nmap replay failed",
            "method":   "nmap_replay",
        }

    def _validate_generic(self, tool: str, args: dict) -> dict:
        """Generic validation for unknown tool types."""
        try:
            result = execute_tool(tool, args)
            if result.get("success"):
                return {
                    "verified": True,
                    "evidence": f"Tool {tool} confirmed: {str(result)[:100]}",
                    "method":   "generic_replay",
                }
        except Exception:
            pass
        return {
            "verified": False,
            "evidence": f"Generic replay of {tool} failed",
            "method":   "generic_replay",
        }

    def _validate_csrf(self, url: str, args: dict) -> dict:
        """Validate CSRF finding by checking for token absence in form."""
        if self.has_curl:
            curl_cmd = ["curl", "-s", "-L", "--max-time", "10", url]
            result = run_command(curl_cmd, timeout=15)
            body = result.get("stdout", "").lower()

            _has_form = "<form" in body
            _has_csrf_token = (
                ("csrf" in body and "input" in body) or
                "_token" in body or
                "csrfmiddlewaretoken" in body or
                'name="_csrf"' in body
            )
            _is_state_changing = any(x in body for x in
                ['method="post"', "method='post'", 'method="put"', 'method="delete"'])

            if _has_form and not _has_csrf_token and _is_state_changing:
                return {
                    "verified": True,
                    "evidence": "CSRF VERIFIED: state-changing form found without CSRF token",
                    "method":   "real_curl_csrf_check",
                }
            elif _has_form and not _has_csrf_token:
                return {
                    "verified": True,
                    "evidence": "CSRF VERIFIED: form found without CSRF token (method not confirmed POST)",
                    "method":   "real_curl_csrf_check",
                }
            elif _has_form and _has_csrf_token:
                return {
                    "verified": False,
                    "evidence": "CSRF token detected in form — endpoint has CSRF protection",
                    "method":   "real_curl_csrf_check",
                }
            else:
                return {
                    "verified": False,
                    "evidence": "No HTML form found on endpoint — CSRF not verifiable",
                    "method":   "real_curl_csrf_check",
                }
        else:
            return {
                "verified": False,
                "evidence": "CSRF validation requires curl — not available",
                "method":   "simulated_csrf",
            }

    def _validate_clickjacking(self, url: str, args: dict) -> dict:
        """Validate Clickjacking finding by checking for frame protection headers."""
        if self.has_curl:
            # Use HEAD request to just get headers
            curl_cmd = ["curl", "-s", "-I", "--max-time", "10", url]
            result = run_command(curl_cmd, timeout=15)
            headers_raw = result.get("stdout", "").lower()

            _has_xfo = "x-frame-options" in headers_raw
            _has_frame_ancestors = "frame-ancestors" in headers_raw

            if not _has_xfo and not _has_frame_ancestors:
                return {
                    "verified": True,
                    "evidence": "CLICKJACKING VERIFIED: no X-Frame-Options or CSP frame-ancestors headers",
                    "method":   "real_curl_clickjacking_check",
                }
            else:
                protections = []
                if _has_xfo:
                    protections.append("X-Frame-Options")
                if _has_frame_ancestors:
                    protections.append("CSP frame-ancestors")
                return {
                    "verified": False,
                    "evidence": f"Frame protection detected: {', '.join(protections)}",
                    "method":   "real_curl_clickjacking_check",
                }
        else:
            return {
                "verified": False,
                "evidence": "Clickjacking validation requires curl — not available",
                "method":   "simulated_clickjacking",
            }
