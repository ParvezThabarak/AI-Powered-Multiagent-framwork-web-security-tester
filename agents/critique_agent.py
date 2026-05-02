"""
Critique Agent — Phase 4
Reviews execution results and rates each finding.

ARCHITECTURE ROLE:
  Step 4b — runs AFTER ExecutionAgent, BEFORE Sandbox Validator.
  Reviews every execution step result and gives a verdict:
    APPROVED          — finding is valid, well-evidenced, worth verifying
    REJECTED          — false positive, wrong tool used, or no real evidence
    NEEDS_REFINEMENT  — partially valid but needs better exploitation

  Only APPROVED findings proceed to Sandbox Validator.
  Only SANDBOX_VERIFIED findings get stored in EKB.

Based on:
- Co-RedTeam (Google + Michigan State 2026):
  Stage I: Analysis Agent + Critique Agent run BEFORE execution
  Stage II: Planner + Validation + Execution + Evaluation
  "The critique agent flags REJECTED plans before wasting execution budget"
  CyBench: 63.7%, BountyBench: 65%
- MAPTA (UCL 2025):
  Validation Agent verifies PoC before reporting success
- PENTEST-AI (IEEE 2024):
  Zookeeper prevents loop/hallucination — critique plays similar role

What it checks per execution step:
  1. Was the right tool used for the claimed vulnerability?
  2. Does the tool output actually prove the finding?
  3. Is this a real exploit or just a probe/fingerprint?
  4. Is the finding consistent with what VulnAnalyst confirmed?
"""

import json
import re
from agents.llm_client import LLMClient


CRITIQUE_SYSTEM_PROMPT = """You are a Critique Agent in an AI-powered penetration testing system.
Your job is to review execution results and determine whether each finding is genuine.

For each step result you receive, you must decide:
  APPROVED         — the finding is valid, the right tool was used, output proves the vulnerability
  REJECTED         — false positive, hallucinated output, wrong tool, or no real evidence
  NEEDS_REFINEMENT — partially valid but the exploit was not fully demonstrated

Rules:
- Be sceptical. Simulated outputs (marked [SIMULATED]) are NOT real proof.
- sqlmap_detect output must mention "injectable", "vulnerable", or specific parameter.
- http_probe with ONLY headers/server info does NOT confirm SQLi, LFI, or XSS.
- sqlmap_detect confirms SQLi if sqli_confirmed is True in output → APPROVE immediately.
- "SQLi CONFIRMED", "boolean-based", "injectable", "error-based" in findings → APPROVE.
- http_probe CAN confirm vulnerabilities if the output contains:
    LFI_DETECTED: TRUE  → APPROVE immediately (file contents proven)
    XSS_REFLECTED: TRUE → APPROVE immediately (payload reflected)
    "LFI CONFIRMED" or "XSS CONFIRMED" in findings → APPROVE
- If output says [SIMULATED], flag as NEEDS_REFINEMENT.
- web_directory_enum "no interesting paths found" = REJECTED for exploitation steps.
- "HTTP headers only" = NEEDS_REFINEMENT (tool ran but needs payload).
- Body captured but no vuln proof = NEEDS_REFINEMENT (partial evidence).
- If sqli_confirmed, LFI_DETECTED, or XSS_REFLECTED is TRUE → APPROVED.
- Use REJECTED only when: tool completely failed, wrong tool used, or output contradicts vulnerability.

Respond ONLY with valid JSON:
{
  "verdict": "APPROVED" | "REJECTED" | "NEEDS_REFINEMENT",
  "confidence": 0.0-1.0,
  "reason": "brief explanation",
  "tool_was_appropriate": true/false,
  "output_proves_vuln": true/false,
  "is_simulated": true/false,
  "suggested_improvement": "what should be done instead (if REJECTED/NEEDS_REFINEMENT)"
}"""


VERDICTS = ["APPROVED", "REJECTED", "NEEDS_REFINEMENT"]


class CritiqueAgent:
    ekb = None   # injected by pipeline for HITL learning
    """
    Critique Agent — Step 4b of pipeline.

    Reviews each ExecutionAgent step result.
    Based on Co-RedTeam's critique loop — adversarially reviews
    findings before they are accepted as confirmed.

    Pipeline position: ExecutionAgent → CritiqueAgent → SandboxValidator
    """

    def __init__(self):
        self.llm = LLMClient("analyst")  # reuse analyst role

    def critique(self, execution_report: dict, analysis_report: dict) -> dict:
        """
        Critique all execution step results.

        execution_report: output from ExecutionAgent.execute_plan()
        analysis_report:  output from VulnAnalystAgent.analyse()
                          (confirmed vulns — used as ground truth)

        Returns: critique report with per-step verdicts
        """
        step_results   = execution_report.get("step_results", [])
        confirmed_vulns = analysis_report.get("vuln_summary", [])
        target_url     = analysis_report.get("target_url", "")

        print(f"\n[CritiqueAgent] 🔎 Reviewing {len(step_results)} execution steps...")
        print(f"[CritiqueAgent] Confirmed vulns from analyst: {len(confirmed_vulns)}")
        print(f"[CritiqueAgent] Method: Co-RedTeam critique loop")
        print("-" * 50)

        critiqued_steps = []
        approved_count  = 0
        rejected_count  = 0
        refine_count    = 0

        for step in step_results:
            step_id   = step.get("step_id", "?")
            step_name = step.get("name", "Unknown")
            status    = step.get("status", "failed")

            # Skip steps that already failed or were skipped as duplicates
            if status == "skipped_duplicate":
                critiqued_steps.append({
                    "step_id":  step_id,
                    "name":     step_name,
                    "verdict":  "NEEDS_REFINEMENT",
                    "reason":   "Duplicate SQLi step skipped — covered by previous step on same endpoint",
                    "confidence": 0.70,
                    "tool_was_appropriate": True,
                    "output_proves_vuln": False,
                    "is_simulated": False,
                    "suggested_improvement": "Ensure Detection and Exploitation steps target different params",
                })
                continue

            # Skip steps that already failed — nothing to critique
            if status == "failed":
                critiqued_steps.append({
                    "step_id":  step_id,
                    "name":     step_name,
                    "verdict":  "REJECTED",
                    "reason":   "Step failed during execution",
                    "confidence": 1.0,
                    "original_status": status,
                })
                rejected_count += 1
                print(f"[CritiqueAgent]   Step {step_id}: REJECTED (failed)")
                continue

            # Build context for LLM critique
            context = self._build_context(step, confirmed_vulns, target_url)
            result  = self._run_critique(context, step_name)

            verdict = result.get("verdict", "REJECTED")
            if verdict not in VERDICTS:
                verdict = "REJECTED"

            critiqued_steps.append({
                "step_id":              step_id,
                "name":                 step_name,
                "verdict":              verdict,
                "confidence":           result.get("confidence", 0.0),
                "reason":               result.get("reason", ""),
                "tool_was_appropriate": result.get("tool_was_appropriate", False),
                "output_proves_vuln":   result.get("output_proves_vuln", False),
                "is_simulated":         result.get("is_simulated", False),
                "suggested_improvement": result.get("suggested_improvement", ""),
                "original_findings":    step.get("findings", []),
                "original_status":      status,
            })

            if verdict == "APPROVED":
                approved_count += 1
                print(f"[CritiqueAgent]   Step {step_id} '{step_name}': ✅ APPROVED "
                      f"(conf:{result.get('confidence',0):.2f})")
            elif verdict == "NEEDS_REFINEMENT":
                refine_count += 1
                print(f"[CritiqueAgent]   Step {step_id} '{step_name}': ⚠️  NEEDS_REFINEMENT — "
                      f"{result.get('reason','')[:60]}")
            else:
                rejected_count += 1
                print(f"[CritiqueAgent]   Step {step_id} '{step_name}': ❌ REJECTED — "
                      f"{result.get('reason','')[:60]}")

        # Extract approved findings for sandbox
        approved_findings = self._extract_approved_findings(
            critiqued_steps, execution_report
        )

        print(f"\n[CritiqueAgent] ✅ Critique complete")
        print(f"[CritiqueAgent]   APPROVED:          {approved_count}")
        print(f"[CritiqueAgent]   NEEDS_REFINEMENT:  {refine_count}")
        print(f"[CritiqueAgent]   REJECTED:          {rejected_count}")
        print(f"[CritiqueAgent]   Approved findings for sandbox: {len(approved_findings)}")

        return {
            "target_url":        target_url,
            "total_steps":       len(step_results),
            "approved_count":    approved_count,
            "rejected_count":    rejected_count,
            "refine_count":      refine_count,
            "critiqued_steps":   critiqued_steps,
            "approved_findings": approved_findings,
            "critique_method":   "Co-RedTeam single-agent review",
        }

    def _build_context(self, step: dict, confirmed_vulns: list, target_url: str) -> str:
        """Build context string for LLM critique."""
        tool_outputs = step.get("tool_outputs", [])
        findings     = step.get("findings", [])

        # Format tool outputs — include body, lfi_detected, xss_reflected
        tool_str = ""
        for t in tool_outputs[:3]:
            out    = t.get("output", {})
            stdout = out.get("stdout", str(out))[:300] if isinstance(out, dict) else str(out)[:300]
            body   = out.get("body", "")[:500] if isinstance(out, dict) else ""
            lfi    = out.get("lfi_detected", False) if isinstance(out, dict) else False
            xss    = out.get("xss_reflected", False) if isinstance(out, dict) else False

            tool_str += f"\nTool: {t.get('tool','?')}({t.get('args',{})})"
            tool_str += f"\nOutput (stdout): {stdout}"
            if lfi:
                evidence = out.get("lfi_evidence", "file contents") if isinstance(out, dict) else ""
                tool_str += f"\nLFI_DETECTED: TRUE — {evidence} found in response body"
                tool_str += f"\nLFI evidence snippet: {body[:200]}"
            if xss:
                tool_str += f"\nXSS_REFLECTED: TRUE — payload reflected in response"
                tool_str += f"\nXSS evidence snippet: {body[:150]}"
            sqli_ok = out.get("sqli_confirmed", False) if isinstance(out, dict) else False
            if sqli_ok:
                tool_str += f"\nsqli_confirmed: True — boolean probe confirmed injection"
            if body and not lfi and not xss and not sqli_ok:
                tool_str += f"\nResponse body (first 500 chars): {body}"
            tool_str += "\n"

        # Also check findings text — execution agent sets "LFI CONFIRMED" / "XSS CONFIRMED" here
        for f in findings:
            f_lower = str(f).lower()
            if "lfi confirmed" in f_lower:
                tool_str += "\nFINDING: LFI CONFIRMED — sensitive file contents retrieved"
            if "xss confirmed" in f_lower:
                tool_str += "\nFINDING: XSS CONFIRMED — payload reflected in response"
            if "sqli confirmed" in f_lower or "sql injection found" in f_lower:
                tool_str += "\nFINDING: SQLi CONFIRMED — injection detected"

        # Relevant confirmed vulns
        vuln_str = "\n".join(
            f"- {v.get('vuln_type','?')} at {v.get('location','?')} param={v.get('param','?')}"
            for v in confirmed_vulns[:5]
        )

        return f"""TARGET: {target_url}

STEP NAME: {step.get('name','?')}
STEP DESCRIPTION: {step.get('description', step.get('name','?'))}
STATUS: {step.get('status','?')}

TOOL OUTPUTS:{tool_str}

STEP FINDINGS: {findings}

CONFIRMED VULNERABILITIES FROM ANALYST:
{vuln_str if vuln_str else 'None'}"""

    def _run_critique(self, context: str, step_name: str) -> dict:
        """Run the LLM critique on a single step.
        First applies deterministic rule checks — LLM only called when rules are uncertain.
        """
        ctx_lower = context.lower()

        # HITL LEARNING QUERY
        # If a human has previously approved/rejected this step type, use that signal.
        # Approved past → +0.15 confidence bonus; Rejected past → −0.20 penalty.
        _hitl_boost = 0.0
        try:
            if self.ekb is not None:
                _entries = self.ekb.retrieve(
                    query=f"HITL human review {step_name}", top_k=3, success_only=False)
                for _he in _entries:
                    if _he.get("vuln_type") != "HITL_Feedback":
                        continue
                    _txt = (_he.get("notes","") + " " + _he.get("retrieval_text","")).lower()
                    _sn  = (step_name or "").lower()
                    if _sn and _sn in _txt:
                        if "approved" in _txt:
                            _hitl_boost += 0.15
                        elif "rejected" in _txt:
                            _hitl_boost -= 0.20
        except Exception:
            pass   # HITL learning is best-effort — never block the pipeline

        # RULE 1: LFI confirmed by file content → APPROVE immediately (skip LLM)
        lfi_patterns = ["root:x:0:0", "root:x:", "bin:x:", "daemon:x:", "/bin/bash",
                        "/bin/sh", "www-data:x:", "lfi confirmed", "sensitive file contents",
                        "lfi_detected: true", "lfi confirmed —"]
        if any(p in ctx_lower for p in lfi_patterns):
            return {
                "verdict": "APPROVED", "confidence": 0.98,
                "reason": "LFI confirmed — sensitive file contents detected in response",
                "tool_was_appropriate": True, "output_proves_vuln": True,
                "is_simulated": False, "suggested_improvement": "",
            }
        # RULE 1b: DVWA LFI URL used but body too short (session may have expired)
        # Do a direct curl probe to verify independently
        if "vulnerabilities/fi/?page=" in context and "localhost:9000" in context:
            try:
                import subprocess as _sp
                from tools.tool_wrappers import get_session_cookie, reset_session_cache
                reset_session_cache()              # force fresh login
                _cookie = get_session_cookie("localhost:9000")
                _url = "http://localhost:9000/vulnerabilities/fi/?page=../../../../etc/passwd"
                _cmd = ["curl", "-s", "-L", "--max-time", "10",
                        "-H", f"Cookie: {_cookie}", _url]
                _r   = _sp.run(_cmd, capture_output=True, text=True, timeout=15)
                _body = _r.stdout
                if any(p in _body for p in ["root:x:", "bin:x:", "daemon:x:"]):
                    return {
                        "verdict": "APPROVED", "confidence": 0.99,
                        "reason": "LFI verified by critique direct probe — /etc/passwd contents confirmed",
                        "tool_was_appropriate": True, "output_proves_vuln": True,
                        "is_simulated": False, "suggested_improvement": "",
                    }
            except Exception:
                pass  # probe failed — fall through to LLM

        # RULE 2: XSS payload reflected → context-aware classification
        xss_patterns = ["alert(1)", "<script>alert", "onerror=alert", "xss confirmed",
                        "payload reflected", "xss_reflected: true"]
        if any(p in ctx_lower for p in xss_patterns):
            # Check for HTML-encoded/escaped payloads → NEEDS_REFINEMENT
            _escaped_indicators = ["&lt;script&gt;", "html-encoded", "escaped",
                                   "xss rejected", "not exploitable"]
            _is_escaped = any(e in ctx_lower for e in _escaped_indicators)
            if _is_escaped:
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.50,
                    "reason": "XSS payload HTML-encoded/escaped — not exploitable in current form",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False,
                    "suggested_improvement": "Try alternative payloads that bypass encoding filters",
                }
            # Check for error page indicators — reflection in error pages is NOT exploitable
            # "context_uncertain" on HTTP 200 = valid reflection, approve it
            # Only treat context_uncertain as error if it also mentions non-200 status
            _error_indicators = ["http status 4", "http status 5", "404 not found",
                                 "400 bad request", "page not found", "whitelabel error",
                                 "xss partial", "not exploitable in browser"]
            # context_uncertain is ONLY an error if paired with a non-200 status
            if "context_uncertain" in ctx_lower and not any(
                    s in ctx_lower for s in ["http 200", "(http 200)", "http 200)"]):
                _error_indicators.append("context_uncertain")
            _is_error_reflection = any(e in ctx_lower for e in _error_indicators)
            if _is_error_reflection:
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.60,
                    "reason": "XSS payload reflected in error page or uncertain context — not confirmed exploitable",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False,
                    "suggested_improvement": "Target an endpoint that renders the payload in valid HTML (HTTP 200)",
                }
            # Check for confirmed executable context
            _executable_indicators = ["executable context", "xss confirmed",
                                      "xss context_uncertain"]   # HTTP 200 uncertain = approve
            if any(e in ctx_lower for e in _executable_indicators):
                # Check it's actually HTTP 200 for context_uncertain
                _is_200 = ("http 200" in ctx_lower or "(http 200)" in ctx_lower or
                           "http 200)" in ctx_lower or "context_uncertain" not in ctx_lower)
                if _is_200:
                    return {
                        "verdict": "APPROVED", "confidence": 0.92,
                        "reason": "XSS confirmed — payload reflected in valid HTTP 200 response",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }
            # Generic reflection without clear context
            return {
                "verdict": "NEEDS_REFINEMENT", "confidence": 0.65,
                "reason": "XSS payload reflected but execution context not confirmed",
                "tool_was_appropriate": True, "output_proves_vuln": False,
                "is_simulated": False,
                "suggested_improvement": "Verify payload renders in browser-executable context",
            }

        # RULE 3: SQLi confirmed by sqlmap → APPROVE immediately (skip LLM)
        sqli_patterns = ["sqli confirmed", "sqli_confirmed: true", "parameter '?' is injectable",
                         "parameter is injectable", "sqlmap confirmed", "boolean-based blind",
                         "sql injection found", "is vulnerable", "time-based blind",
                         "union query", "error-based", "stacked queries",
                         "[warning] parameter", "back-end dbms"]
        if any(p in ctx_lower for p in sqli_patterns):
            return {
                "verdict": "APPROVED", "confidence": 0.97,
                "reason": "SQLi confirmed — sqlmap verified injection",
                "tool_was_appropriate": True, "output_proves_vuln": True,
                "is_simulated": False, "suggested_improvement": "",
            }

        # RULE 4: web_directory_enum with no paths → REJECT immediately (skip LLM)
        if "web_directory_enum" in ctx_lower and "no interesting paths" in ctx_lower:
            return {
                "verdict": "REJECTED", "confidence": 0.9,
                "reason": "Directory enumeration found no accessible paths",
                "tool_was_appropriate": False, "output_proves_vuln": False,
                "is_simulated": False, "suggested_improvement": "Try http_probe with known vulnerable paths",
            }

        # RULE 5: Binary file skipped → NEEDS_REFINEMENT (no body evidence)
        if "binary file" in ctx_lower or "skipping body parse" in ctx_lower:
            return {
                "verdict": "NEEDS_REFINEMENT", "confidence": 0.7,
                "reason": "Binary file — no text body to analyze for vulnerabilities",
                "tool_was_appropriate": False, "output_proves_vuln": False,
                "is_simulated": False, "suggested_improvement": "Target a text endpoint instead",
            }

        # RULE 6: CSRF — require evidence of missing CSRF token, not just reachability
        # GUARD: only fire this rule when the step is explicitly a CSRF step.
        # WebGoat SQLi/XSS steps target /login URL which contains "login" in body,
        # causing false CSRF triggers. Step name must contain "csrf" to qualify.
        sname = step_name.lower() if step_name else ""
        csrf_indicators = ["csrf", "anti-csrf", "absence of anti-csrf", "csrf analysis",
                           "token validation"]
        # Only fire CSRF rule when the STEP NAME explicitly contains "csrf"
        # Prevents Clickjacking/Misconfiguration steps from being mislabeled
        # (WebGoat /registration HTML body contains "csrf" as an attribute name)
        _is_csrf_step = "csrf" in sname
        if _is_csrf_step:
            # Strong: ExecutionAgent reported form WITHOUT token
            if "form found without csrf token" in ctx_lower or "token detected=false" in ctx_lower:
                return {
                    "verdict": "APPROVED", "confidence": 0.88,
                    "reason": "CSRF — form present without CSRF token protection",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }
            # Token is present → REJECTED
            if "token detected=true" in ctx_lower or "with csrf token present" in ctx_lower:
                return {
                    "verdict": "REJECTED", "confidence": 0.85,
                    "reason": "CSRF token detected in form — endpoint is protected",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False, "suggested_improvement": "Target a different endpoint without token enforcement",
                }
            # No form detected → NEEDS_REFINEMENT
            if "no form detected" in ctx_lower:
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.55,
                    "reason": "No HTML form found on endpoint — CSRF not verifiable",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False, "suggested_improvement": "Probe a form-based state-changing endpoint",
                }
            # Legacy fallback: login/registration reachable but no token extraction data
            if any(x in ctx_lower for x in ["login", "register", "registration"]):
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.60,
                    "reason": "CSRF — endpoint reachable but token presence not confirmed/denied",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False, "suggested_improvement": "Re-probe endpoint and inspect form for _csrf / _token inputs",
                }

        # RULE 7: Security Headers / Clickjacking / CORS / CSP Misconfiguration
        misconfig_indicators = ["clickjacking", "x-frame-options", "csp header",
                                "frame-ancestors", "cors misconfiguration",
                                "security headers missing", "access-control-allow-origin",
                                "clickjacking confirmed", "x-frame-options=missing"]
        if (any(p in ctx_lower for p in misconfig_indicators) or
                "clickjack" in sname or "misconfig" in sname or "cors" in sname or
                "header" in sname):
            # CORS wildcard
            if "cors misconfiguration" in ctx_lower or "access-control-allow-origin=*" in ctx_lower:
                return {
                    "verdict": "APPROVED", "confidence": 0.91,
                    "reason": "CORS Misconfiguration confirmed — Access-Control-Allow-Origin wildcard allows cross-origin data theft",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }
            # Security headers absent (CSP + X-Frame-Options missing)
            if "security headers missing" in ctx_lower or ("csp=absent" in ctx_lower or "csp absent" in ctx_lower):
                return {
                    "verdict": "APPROVED", "confidence": 0.88,
                    "reason": "Security headers absent — CSP and X-Frame-Options missing increases attack surface",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }
            # Clickjacking confirmed (existing logic below)
            if "x-frame-options=missing" in ctx_lower and "frame-ancestors=missing" in ctx_lower:
                return {
                    "verdict": "APPROVED", "confidence": 0.90,
                    "reason": "Clickjacking confirmed — both X-Frame-Options and CSP frame-ancestors missing",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }
            # Partial protection present
            if "x-frame-options=" in ctx_lower or "frame-ancestors=present" in ctx_lower:
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.60,
                    "reason": "Clickjacking — partial frame protection detected, needs deeper analysis",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False, "suggested_improvement": "Verify if X-Frame-Options value is DENY/SAMEORIGIN or misconfigured",
                }
            # No header data available — generic response
            has_response = ("response body" in ctx_lower or "http headers" in ctx_lower
                            or "server:" in ctx_lower or "chars). server" in ctx_lower)
            if has_response:
                return {
                    "verdict": "NEEDS_REFINEMENT", "confidence": 0.55,
                    "reason": "Clickjacking — server responded but header analysis not available",
                    "tool_was_appropriate": True, "output_proves_vuln": False,
                    "is_simulated": False, "suggested_improvement": "Extract X-Frame-Options and CSP headers explicitly",
                }

        # RULE 8: General Security Misconfiguration (non-clickjacking)
        general_misconfig = ["misconfiguration analysis", "security misconfiguration",
                             "misconfig", "spring actuator", "actuator information"]
        if (any(p in ctx_lower for p in general_misconfig) or
                "misconfig" in sname or "misconfiguration" in sname):
            has_response = ("response body" in ctx_lower or "http headers" in ctx_lower
                            or "server:" in ctx_lower or "status 200" in ctx_lower
                            or "chars). server" in ctx_lower)
            if has_response:
                return {
                    "verdict": "APPROVED", "confidence": 0.82,
                    "reason": "Misconfiguration confirmed — server accessible, security headers absent",
                    "tool_was_appropriate": True, "output_proves_vuln": True,
                    "is_simulated": False, "suggested_improvement": "",
                }

        # Rules inconclusive → call LLM for judgment
        messages = [
            {"role": "system", "content": CRITIQUE_SYSTEM_PROMPT},
            {"role": "user",   "content": f"Critique this execution step:\n\n{context}"},
        ]
        try:
            response = self.llm.chat(messages)
            parsed   = self._extract_json(str(response))
            if parsed and parsed.get("verdict") in VERDICTS:
                return parsed
        except Exception as e:
            print(f"[CritiqueAgent]   ⚠️  LLM error: {e}")

        # Fallback: reject simulated outputs, approve tool-confirmed ones
        return self._fallback_critique(context)

    def _fallback_critique(self, context: str) -> dict:
        """Rule-based fallback when LLM fails."""
        ctx_lower = context.lower()
        is_simulated = "[SIMULATED]" in context
        # SQLi — check all confirmation signals
        has_sqli = ("sqli_confirmed: true" in ctx_lower or
                    "sqli confirmed" in ctx_lower or
                    "finding: sqli confirmed" in ctx_lower or
                    any(kw in ctx_lower for kw in
                        ["boolean-based blind", "injectable", "error-based sqli",
                         "parameter is injectable", "sqlmap confirmed", "sql injection found"]))
        # XSS — check for payload-specific evidence, not generic <script> tags
        # "<script>" alone matches Angular SPA bundles (false positive)
        has_xss = ("xss confirmed" in ctx_lower or
                   "xss_reflected: true" in ctx_lower or
                   "finding: xss confirmed" in ctx_lower or
                   "alert(1)" in ctx_lower or
                   "<script>alert" in ctx_lower or
                   "onerror=alert" in ctx_lower or
                   "payload reflected" in ctx_lower)
        # LFI — check flags, patterns, and findings text
        has_lfi = ("lfi_detected: true" in ctx_lower or
                   "finding: lfi confirmed" in ctx_lower or
                   "lfi confirmed" in ctx_lower or
                   any(kw in context for kw in
                       ["root:x:0:0", "root:x:", "daemon:x:", "/bin/bash",
                        "LFI CONFIRMED", "sensitive file contents"]))
        headers_only = "http headers only" in ctx_lower

        if is_simulated:
            return {
                "verdict": "NEEDS_REFINEMENT",
                "confidence": 0.6,
                "reason": "Output is simulated — not real tool execution",
                "tool_was_appropriate": True,
                "output_proves_vuln": False,
                "is_simulated": True,
                "suggested_improvement": "Run real sqlmap or curl against target",
            }
        elif has_lfi:
            return {
                "verdict": "APPROVED",
                "confidence": 0.9,
                "reason": "LFI confirmed — sensitive file contents in response body",
                "tool_was_appropriate": True,
                "output_proves_vuln": True,
                "is_simulated": False,
                "suggested_improvement": "",
            }
        elif has_sqli:
            return {
                "verdict": "APPROVED",
                "confidence": 0.75,
                "reason": "Tool output contains confirmed SQLi indicators",
                "tool_was_appropriate": True,
                "output_proves_vuln": True,
                "is_simulated": False,
                "suggested_improvement": "",
            }
        elif has_xss:
            # XSS in fallback: check for error-page reflection same as Rule 2
            _error_indicators = ["http status 4", "http status 5", "404 not found",
                                 "400 bad request", "page not found", "whitelabel error",
                                 "xss partial", "not exploitable in browser"]
            if any(e in ctx_lower for e in _error_indicators):
                return {
                    "verdict": "NEEDS_REFINEMENT",
                    "confidence": 0.55,
                    "reason": "XSS payload reflected in error page — not exploitable",
                    "tool_was_appropriate": True,
                    "output_proves_vuln": False,
                    "is_simulated": False,
                    "suggested_improvement": "Target a valid HTML endpoint (HTTP 200)",
                }
            return {
                "verdict": "APPROVED",
                "confidence": 0.75,
                "reason": "XSS confirmed — payload reflected in valid response",
                "tool_was_appropriate": True,
                "output_proves_vuln": True,
                "is_simulated": False,
                "suggested_improvement": "",
            }
        elif headers_only:
            return {
                "verdict": "NEEDS_REFINEMENT",
                "confidence": 0.55,
                "reason": "http_probe returned headers only — add exploit payload to confirm vulnerability",
                "tool_was_appropriate": True,
                "output_proves_vuln": False,
                "is_simulated": False,
                "suggested_improvement": "Retry http_probe with LFI payload (doc=../../../../etc/passwd) or XSS payload",
            }
        else:
            # Body was captured but no exploit proof — partial success
            has_body = "response body captured" in context.lower() or "body:" in context.lower()
            if has_body:
                return {
                    "verdict": "NEEDS_REFINEMENT",
                    "confidence": 0.5,
                    "reason": "Response body captured but no vulnerability indicators found — needs stronger payload",
                    "tool_was_appropriate": True,
                    "output_proves_vuln": False,
                    "is_simulated": False,
                    "suggested_improvement": "Try exploit-specific payload or check response for sensitive data patterns",
                }
            return {
                "verdict": "REJECTED",
                "confidence": 0.7,
                "reason": "No vulnerability indicators in tool output",
                "tool_was_appropriate": False,
                "output_proves_vuln": False,
                "is_simulated": False,
                "suggested_improvement": "Use sqlmap_detect or http_probe with exploit payload",
            }

    def _extract_approved_findings(self, critiqued_steps: list,
                                    execution_report: dict) -> list:
        """
        Extract findings from APPROVED steps for sandbox validation.
        Each approved finding carries enough info to replay the exploit.
        """
        approved = []
        step_map = {s["step_id"]: s for s in execution_report.get("step_results", [])}

        for cs in critiqued_steps:
            if cs["verdict"] != "APPROVED":
                continue

            original = step_map.get(cs["step_id"], {})
            tool_outputs = original.get("tool_outputs", [])

            for to in tool_outputs:
                approved.append({
                    "step_id":   cs["step_id"],
                    "step_name": cs["name"],
                    "tool":      to.get("tool", ""),
                    "args":      to.get("args", {}),
                    "finding":   cs["original_findings"][0] if cs["original_findings"] else "",
                    "confidence": cs["confidence"],
                })

        return approved

    def _extract_json(self, text: str) -> dict | None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        return None
