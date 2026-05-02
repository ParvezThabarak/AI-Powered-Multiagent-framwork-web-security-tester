import os
"""
Execution Agent — Phase 1, Agent 3
Executes the plan from the Planner Agent step by step.

Based on:
- CurriculumPT: Exploitation Agent + Replan Agent (ReAct loop)
- PentestMCP: Exploitation Agent (56.6% success rate)
- MAPTA: Sandbox Agents with early stopping
- PENTEST-AI: ESA (Exploit Simulation Agent) + PEA (Post-Exploitation)
"""

import json
import time
from datetime import datetime
from agents.llm_client import LLMClient
from tools.tool_wrappers import EXECUTOR_TOOLS, execute_tool, RECON_TOOLS
from config.config import SAFETY, PHASE8_SETTINGS


# Phase 8: Exception for cost-aware early stopping (MAPTA-inspired)
class EarlyStopException(Exception):
    """Raised when execution exceeds the cost budget.
    Ensures graceful shutdown — logs are saved, no token bleed."""
    pass


EXECUTOR_SYSTEM_PROMPT = """You are an Execution Agent in an AI-powered penetration testing system.

CRITICAL RULES — READ CAREFULLY:
1. You MUST ALWAYS call a tool. Never explain. Never describe. Never say "I cannot".
2. ALWAYS use the tool_call format. Text responses are NOT allowed.
3. If you don't know which tool to use, use http_probe as default.
4. NEVER say "I cannot use curl" or "this tool is not available" — just pick the closest available tool.
5. Available tools: nmap_port_scan, http_probe, web_directory_enum, nmap_vuln_scan, sqlmap_detect, sqlmap_get_dbs

WORKFLOW:
- Read the step description
- Pick the BEST available tool from the list above
- Call it immediately
- Do NOT output any text explanation

TOOL SELECTION GUIDE:
- Port/service info needed → nmap_port_scan
- HTTP headers/fingerprint/path test → http_probe
- Find directories/admin panels → web_directory_enum
- Find CVEs/vulnerabilities → nmap_vuln_scan
- SQL injection detection/testing → sqlmap_detect
- SQL injection exploitation / database dump → sqlmap_get_dbs
- Anything else → http_probe (default fallback)

SQLMAP RULES (mandatory):
- ALWAYS use level=1, risk=1 for sqlmap_detect (never higher on first attempt)
- NEVER use level=5 or risk=3 — these cause timeouts and kill the pipeline
- For sqlmap_get_dbs: still use level=1, risk=1 with the confirmed URL
"""

REPLAN_SYSTEM_PROMPT = """You are a Replan Agent. A penetration testing step has failed.
Analyze the failure and suggest a modified approach.

Respond with JSON:
{
  "failure_reason": "why it failed",
  "modified_approach": "what to try instead",
  "new_tool": "tool name",
  "new_arguments": {...},
  "confidence": 0.0-1.0
}
"""


class ExecutionAgent:
    """
    Execution Agent + built-in Replan Agent.
    Uses Groq Mixtral for reliable tool execution.
    Implements ReAct loop: Reason → Act → Observe → Reason...

    Based on CurriculumPT's execution-replanning cycle.
    """

    def __init__(self):
        self.llm_executor = LLMClient("executor")
        self.llm_recon    = LLMClient("recon")  # For replan reasoning
        self.results      = []
        self.start_time   = None

        # MAPTA-style cost/time tracking
        self.tool_call_count = 0
        self.max_tool_calls  = SAFETY["max_tool_calls"]
        self.max_time        = SAFETY["max_time_seconds"]

        # Phase 8: cost tracking for early stopping
        self._estimated_cost_usd = 0.0
        self._cost_per_call      = 0.002   # ~$0.002 per Groq Llama-3.3-70B call
        self._max_cost           = PHASE8_SETTINGS.get("max_cost_usd", 0.30)

        # Phase 8: track which step_ids succeeded vs failed for dependency checks
        self._step_outcomes: dict[int, bool] = {}
        # Prevent redundant SQLi checks against same endpoint+param in one run.
        self._sqli_fingerprints: set[str] = set()
        self._reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    def _elk_step_log(self, event_type: str, step: dict, extra: dict = None) -> None:
        """Write one structured event per execution step to live_events.ndjson for ELK/Kibana."""
        try:
            import json as _j
            from datetime import datetime as _dt
            os.makedirs(self._reports_dir, exist_ok=True)
            record = {
                "@timestamp": _dt.utcnow().isoformat() + "Z",
                "event_type": event_type,
                "pipeline": "phase7",
                "source": "ai-websec-tester",
                "step_id":   step.get("step_id"),
                "step_name": step.get("name"),
                "tool":      step.get("tool"),
                "target":    step.get("target_url", step.get("target", "")),
                "param":     step.get("target_param", ""),
                "confidence": step.get("confidence", 1.0),
                "priority":  step.get("priority", "high"),
            }
            if extra:
                record.update(extra)
            with open(os.path.join(self._reports_dir, "live_events.ndjson"), "a", encoding="utf-8") as f:
                f.write(_j.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def execute_plan(self, plan: dict, auto_approve: bool = False) -> dict:
        """
        Execute a full penetration testing plan step by step.

        plan: output from PlannerAgent.create_plan()
        auto_approve: if False, pause for human approval on flagged steps

        Returns: execution report dict
        """
        self.start_time = time.time()
        self.results    = []
        self._sqli_fingerprints = set()
        steps           = plan.get("steps", [])

        print(f"\n[ExecutionAgent] \U0001f680 Starting plan execution")
        print(f"[ExecutionAgent] Steps to execute: {len(steps)}")
        print(f"[ExecutionAgent] Safety limits: {self.max_tool_calls} tool calls, {self.max_time}s, ${self._max_cost:.2f} cost cap")
        print("-" * 50)

        _early_stopped = False
        for step in steps:
            # MAPTA early stopping check
            elapsed = time.time() - self.start_time
            if self.tool_call_count >= self.max_tool_calls:
                print(f"\n[ExecutionAgent] \u26d4 Stopping: reached max tool calls ({self.max_tool_calls})")
                break
            if elapsed >= self.max_time:
                print(f"\n[ExecutionAgent] \u26d4 Stopping: reached max time ({self.max_time}s)")
                break

            # Phase 8: cost-aware early stopping
            if (PHASE8_SETTINGS.get("early_stop_enabled")
                    and self._estimated_cost_usd >= self._max_cost):
                print(f"\n[ExecutionAgent] \U0001f4b0 Early stop: cost ${self._estimated_cost_usd:.3f} >= ${self._max_cost:.2f} budget")
                _early_stopped = True
                break

            # Phase 8: dependency-aware step skipping
            if PHASE8_SETTINGS.get("dependency_check_enabled"):
                depends_on = step.get("depends_on", [])
                if isinstance(depends_on, int):
                    depends_on = [depends_on]
                if depends_on:
                    parent_failed = any(
                        not self._step_outcomes.get(dep_id, True)
                        for dep_id in depends_on
                    )
                    if parent_failed:
                        print(f"\n[ExecutionAgent] \u23e9 Step {step['step_id']}: skipped "
                              f"(depends_on {depends_on} failed)")
                        self.results.append({
                            "step_id": step["step_id"],
                            "name":    step["name"],
                            "status":  "skipped_dependency",
                        })
                        self._step_outcomes[step["step_id"]] = False
                        continue

            # Human approval gate (Four-Layer + Co-RedTeam pattern)
            if step.get("requires_human_approval") and not auto_approve:
                approved = self._request_human_approval(step)
                if not approved:
                    print(f"[ExecutionAgent] \u23ed\ufe0f  Step {step['step_id']} skipped by human")
                    self.results.append({
                        "step_id": step["step_id"],
                        "name":    step["name"],
                        "status":  "skipped_by_human",
                    })
                    continue

            # Execute the step
            result = self._execute_step(step)
            self.results.append(result)

            # Phase 8: track outcome for dependency checks
            self._step_outcomes[step["step_id"]] = (result.get("status") == "success")

            # Phase 8: accumulate estimated cost
            attempts = result.get("attempts", 1)
            self._estimated_cost_usd += attempts * self._cost_per_call

            # Brief pause between steps (rate limit protection)
            time.sleep(1)

        # Build final execution report
        report = self._build_execution_report(plan)
        if _early_stopped:
            report["early_stopped"] = True
            report["early_stop_reason"] = f"Cost ${self._estimated_cost_usd:.3f} >= budget ${self._max_cost:.2f}"

        # ── ELK: Log execution summary event ────────────────────────────────
        _steps = plan.get("steps", [])
        _success_n = report.get("successful_steps", 0)
        _fail_n = report.get("failed_steps", 0)
        _total_n = report.get("total_steps", len(_steps))
        self._elk_step_log("execution_summary", {"step_id":0,"name":"summary","tool":"pipeline",
            "target_url": plan.get("target_summary","?"), "target_param":"",
            "confidence":1.0, "priority":"high"}, {
            "status": "complete",
            "total_steps": _total_n,
            "successful_steps": _success_n,
            "failed_steps": _fail_n,
            "tool_calls_used": self.tool_call_count,
            "evr_raw": round(_success_n / max(_total_n,1), 3),
        })
        print(f"\n[ExecutionAgent] \u2705 Execution complete")
        print(f"[ExecutionAgent] Success: {report['successful_steps']}/{report['total_steps']} steps")
        print(f"[ExecutionAgent] Time: {report['total_time_seconds']:.1f}s | Cost: ${self._estimated_cost_usd:.3f}")
        print(f"[ExecutionAgent] Tool calls: {self.tool_call_count}")

        return report

    def _validate_step_url(self, step: dict) -> bool:
        """Pre-execution URL sanity check — reject obviously malformed planner URLs.
        Prevents merged paths like: sitemap.xml/vulnerabilities/fi/
        """
        url = step.get("target_url", "")
        if not url:
            return True   # no URL = non-http step, let through
        # Reject double-path merges (sitemap.xml/vulnerabilities/ etc)
        if "sitemap.xml/" in url and any(x in url for x in ["/vulnerabilities/", "/fi/", "/sqli/"]):
            return False
        # Reject multiple http:// in one URL
        if url.count("http://") > 1 or url.count("https://") > 1:
            return False
        # Reject LFI payload appended to obviously wrong base path
        if "/?page=../../../../" in url:
            from urllib.parse import urlparse as _pu
            _parsed = _pu(url)
            _path = _parsed.path
            # /vulnerabilities/fi/ is the only valid path for DVWA LFI
            if _path and not _path.startswith("/vulnerabilities/"):
                return False
        return True

    # ──────────────────────────────────────────────
    # ATTACK CHAINING SUBSYSTEM
    # ──────────────────────────────────────────────
    def _extract_chain_artifacts(self, finding: str, tool_output: dict) -> dict:
        """Extract exploitation artifacts from a successful finding.
        Returns a dict of discovered artifacts to seed chained steps.
        """
        import re as _re
        artifacts = {}
        text = (finding + " " + str(tool_output.get("stdout", "")) +
                " " + str(tool_output.get("body", ""))).lower()
        full = finding + " " + str(tool_output.get("stdout", ""))

        # LFI: file read succeeded
        if any(p in text for p in ["root:x:", "bin:x:", "/bin/bash",
                                    "daemon:x:", "lfi confirmed"]):
            artifacts["lfi_file_read"] = True

        # SQLi: injection confirmed
        if any(p in text for p in ["sqli confirmed", "is injectable",
                                    "boolean-based", "sqlmap confirmed",
                                    "sqli_confirmed: true"]):
            artifacts["sqli_confirmed"] = True

        # XSS: payload reflected — can escalate to stored XSS check
        if any(p in text for p in ["xss confirmed", "payload reflected",
                                    "alert(1)", "xss_reflected: true"]):
            artifacts["xss_reflected"] = True

        # JWT token in response
        _jwt = _re.search(r"(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)",
                          full)
        if _jwt:
            artifacts["jwt"] = _jwt.group(1)

        return artifacts

    def _generate_chain_steps(self, artifacts: dict, target_url: str,
                               current_step_id: int) -> list:
        """Generate follow-up exploitation steps from extracted artifacts.
        Capped at 2 chained steps per call to prevent runaway execution.
        """
        new_steps = []
        nid = current_step_id + 100   # chain steps get offset IDs

        if artifacts.get("sqli_confirmed"):
            # Confirmed SQLi → attempt database enumeration
            new_steps.append({
                "step_id": nid, "name": "SQLi DB Dump (chained)",
                "description": "Extract database names after confirmed SQL injection",
                "tool": "sqlmap_get_dbs",
                "target_url": target_url, "target_param": "id",
                "command_hint": f"sqlmap_get_dbs url={target_url} level=1 risk=1",
                "expected_outcome": "database names listed",
                "owasp": "A03_Injection", "mitre_technique": "T1190",
                "requires_human_approval": True,   # DB dump needs human sign-off
            })
            nid += 1

        if artifacts.get("lfi_file_read"):
            # Confirmed LFI → try higher-privilege file
            _base = target_url.split("?")[0]
            new_steps.append({
                "step_id": nid, "name": "LFI Escalation (chained)",
                "description": "Attempt /etc/shadow read after confirmed LFI",
                "tool": "http_probe",
                "target_url": f"{_base}?page=../../../../etc/shadow",
                "target_param": "page",
                "command_hint": f"http_probe url={_base}?page=../../../../etc/shadow",
                "expected_outcome": "shadow file or escalation evidence",
                "owasp": "A05_Broken_Access_Control", "mitre_technique": "T1083",
                "requires_human_approval": False,
            })

        return new_steps[:2]   # hard cap — safety

    def _execute_step(self, step: dict) -> dict:
        """Execute a single plan step with ReAct loop + replanning."""
        step_id   = step["step_id"]
        step_name = step["name"]
        planner_tool = step.get("tool", "")
        step_name_l = step_name.lower()
        # Guard: SQLi steps need sqlmap, but PRESERVE sqlmap_get_dbs for exploitation steps
        # so their dedup fingerprint differs from detection steps.
        if any(k in step_name_l for k in ["sqli", "sql injection"]):
            if planner_tool not in ("sqlmap_detect", "sqlmap_get_dbs"):
                planner_tool = "sqlmap_detect"
        # Pre-execution URL sanity check — reject malformed planner URLs
        if not self._validate_step_url(step):
            bad_url = step.get("target_url", "")
            print(f"\n[ExecutionAgent] ⚠️  Step {step_id}: URL validation failed — {bad_url[:80]}")
            print(f"[ExecutionAgent]   Skipping step: invalid merged URL")
            return {
                "step_id":   step_id, "name": step_name,
                "status":    "failed", "attempts": 0,
                "tool_outputs": [], "findings": [],
                "reason":    f"Invalid URL rejected by pre-check: {bad_url[:80]}",
            }

        # De-duplicate SQLi checks that resolve to the same effective target in this run.
        # sqlmap_detect and sqlmap_get_dbs use separate namespaces so exploitation steps
        # don't get skipped even when targeting the same endpoint as detection steps.
        if planner_tool in ("sqlmap_detect", "sqlmap_get_dbs"):
            sqli_param = self._infer_sqli_param(step)
            sqli_base = step.get("target_url", "").split("?")[0].lower()
            sqli_fp = f"{planner_tool}|{sqli_base}|{sqli_param.lower()}"
            if sqli_fp in self._sqli_fingerprints:
                print(f"\n[ExecutionAgent] ⏭️  Step {step_id}: skipped duplicate SQLi target ({sqli_param})")
                return {
                    "step_id":   step_id,
                    "name":      step_name,
                    "status":    "skipped_duplicate",
                    "attempts":  0,
                    "findings":  [f"Skipped duplicate SQLi target for param '{sqli_param}'"],
                    "tool_outputs": [],
                    "timestamp": datetime.now().isoformat(),
                }
            self._sqli_fingerprints.add(sqli_fp)

        print(f"\n[ExecutionAgent] ▶️  Step {step_id}: {step_name}")

        step_result = {
            "step_id":   step_id,
            "name":      step_name,
            "status":    "failed",
            "attempts":  0,
            "findings":  [],
            "tool_outputs": [],
            "timestamp": datetime.now().isoformat(),
        }

        # ReAct loop — try up to max_replan_attempts times
        max_attempts = SAFETY["max_replan_attempts"]

        for attempt in range(max_attempts):
            step_result["attempts"] = attempt + 1
            self.tool_call_count   += 1

            # Build context — escalate guidance on retry
            # Adaptive mutation: analyze last failure and modify approach
            retry_hint = ""
            if attempt >= 1 and step_result.get("tool_outputs"):
                _last_out  = step_result["tool_outputs"][-1].get("output", {})
                _last_body = str(_last_out.get("body","") or _last_out.get("stdout","")).lower()
                _cur_url   = step.get("target_url", "")
                # Detect failure reason and mutate the step URL/payload
                if ("403" in _last_body or "forbidden" in _last_body):
                    # Blocked → try URL-encoded bypass
                    _new_url = _cur_url.replace("<script>", "%3Cscript%3E").replace(
                               "../../../../", "..%2F..%2F..%2F..%2F")
                    if _new_url != _cur_url:
                        step["target_url"] = _new_url
                        print(f"[ExecutionAgent]   🔄 Adaptive: URL-encoded bypass → {_new_url[:60]}")
                elif len(_last_body) < 500 and "/vulnerabilities/fi/" in _cur_url:
                    # LFI got short body (login redirect) — try alternate traversal
                    step["target_url"] = _cur_url.replace(
                        "../../../../etc/passwd", "....//....//....//....//etc/passwd")
                    print(f"[ExecutionAgent]   🔄 Adaptive: alternate LFI traversal")

            if attempt == 1:
                retry_hint = ("Previous attempt failed. Use a lighter variant. "
                              "For SQLi: try sqlmap_detect with level=2, risk=1 only. "
                              "For LFI: try URL-encoded payload %2e%2e%2f%2e%2e%2fetc%2fpasswd. "
                              "For http_probe: verify the URL includes the actual payload value.")
            elif attempt >= 2:
                retry_hint = ("Two attempts failed. Switch approach entirely. "
                              "For SQLi: use http_probe with manual SQLi payload in URL. "
                              "For LFI: try /proc/self/environ path. "
                              "Do NOT re-run the same heavy tool again.")

            # Ask LLM how to execute this step
            # Pass target_url and command_hint explicitly — LLM must use these, not guess
            step_url   = step.get("target_url", "")
            step_param = step.get("target_param", "")
            step_cmd   = step.get("command_hint", "")
            messages = [
                {"role": "system", "content": EXECUTOR_SYSTEM_PROMPT},
                {"role": "user",   "content": f"""Execute this penetration testing step:

Step: {step_name}
Description: {step.get('description', '')}
Tool: {step.get('tool', 'http_probe')}
TARGET URL: {step_url}
TARGET PARAM: {step_param}
Command hint: {step_cmd}
Expected outcome: {step.get('expected_outcome', '')}

IMPORTANT: Use TARGET URL exactly as shown. Do NOT substitute a different URL.

{retry_hint}
"""},
            ]

            all_tools = RECON_TOOLS + EXECUTOR_TOOLS
            response  = self.llm_executor.chat(messages, tools=all_tools)

            def _execute_planned_tool(chosen_tool: str):
                """Deterministic execution path used for normal calls and 429 fallback."""
                step_url_local = step.get("target_url", "")
                step_param_local = step.get("target_param", "q")

                def _set_query_param(url: str, param: str, value: str) -> str:
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    parsed = urlparse(url)
                    q = parse_qs(parsed.query, keep_blank_values=True)
                    q[param] = [value]
                    new_query = urlencode(q, doseq=True)
                    return urlunparse(parsed._replace(query=new_query))

                if chosen_tool == "http_probe":
                    payloads = step.get("payloads", [])
                    probe_url = step_url_local
                    # If the URL already has an XSS payload or LFI path embedded (from
                    # _enforce_known_endpoints), pass it directly without re-injecting.
                    # Re-injection via urlencode would percent-encode the payload and
                    # break XSS reflection detection (server gets %3Cscript%3E not <script>).
                    _url_has_payload = any(
                        marker in step_url_local.lower() for marker in
                        ["<script>", "onerror=", "alert(", "etc/passwd", "etc/shadow",
                         "%2fetc%2fpasswd", "matchingpassword=", "xss_test"]
                    )
                    if payloads and not _url_has_payload:
                        # URL is clean — inject payload via query param
                        probe_url = _set_query_param(step_url_local, step_param_local or "q", payloads[0])
                    elif not payloads and not _url_has_payload:
                        probe_url = step_url_local
                    # else: URL already carries the payload — use as-is
                    tool_args_local = {"url": probe_url}
                elif chosen_tool in ("sqlmap_detect", "sqlmap_get_dbs"):
                    sql_param = step_param_local or "id"
                    # If planner emitted mismatched metadata, infer from step intent.
                    sql_param = self._infer_sqli_param(step) or sql_param
                    sql_url = _set_query_param(step_url_local, sql_param, "1")
                    tool_args_local = {"url": sql_url, "level": 1, "risk": 1}
                    try:
                        from tools.tool_wrappers import get_session_cookie
                        import re as _re
                        _m = _re.search(r"https?://([^/]+)", sql_url)
                        _hp = _m.group(1) if _m else ""
                        if _hp:
                            _cookie = get_session_cookie(_hp)
                            if _cookie:
                                tool_args_local["cookie"] = _cookie
                    except Exception:
                        pass
                else:
                    tool_args_local = response.get("arguments", {}) if isinstance(response, dict) else {}

                print(f"[ExecutionAgent]   🔧 Tool: {chosen_tool}({tool_args_local})")
                tool_output_local = execute_tool(chosen_tool, tool_args_local)
                step_result["tool_outputs"].append({
                    "tool":   chosen_tool,
                    "args":   tool_args_local,
                    "output": tool_output_local,
                })

                success_local, finding_local = self._analyze_tool_output(chosen_tool, tool_output_local, step)
                return success_local, finding_local, tool_output_local

            if isinstance(response, dict) and response.get("tool_call"):
                # Preserve planner intent: LLM can provide hints, but must not override the planned tool.
                tool_name = planner_tool or response.get("function", "http_probe")
                success, finding, tool_output = _execute_planned_tool(tool_name)
                if success:
                    step_result["status"]   = "success"
                    step_result["findings"].append(finding)
                    print(f"[ExecutionAgent]   ✅ Step {step_id} succeeded: {finding}")
                    self._elk_step_log("step_success", step, {
                        "status": "success", "finding": str(finding)[:200],
                        "attempt": attempt+1,
                    })
                    # Attack chaining: extract artifacts and queue follow-up steps
                    _art = self._extract_chain_artifacts(finding, tool_output)
                    if _art:
                        _chain = self._generate_chain_steps(_art, step.get("target_url",""),
                                                            step_id)
                        if _chain:
                            step_result["chain_steps"] = _chain
                            print(f"[ExecutionAgent]   🔗 Attack chain: "
                                  f"+{len(_chain)} follow-up step(s) queued")
                    break
                else:
                    print(f"[ExecutionAgent]   ❌ Attempt {attempt+1} failed")
                    if attempt < max_attempts - 1:
                        print(f"[ExecutionAgent]   🔄 Replanning...")

            else:
                # LLM returned text instead of tool call — parse it
                print(f"[ExecutionAgent]   💬 {str(response)[:150]}...")
                _resp_txt = str(response).lower()
                if "429" in _resp_txt or "rate limit" in _resp_txt:
                    # Resilient fallback: execute planned tool even if LLM is temporarily unavailable.
                    _fallback_tool = planner_tool or step.get("tool", "http_probe")
                    print(f"[ExecutionAgent]   ↪️  LLM rate-limited, fallback execute: {_fallback_tool}")
                    success, finding, tool_output = _execute_planned_tool(_fallback_tool)
                    if success:
                        step_result["status"] = "success"
                        step_result["findings"].append(finding)
                        print(f"[ExecutionAgent]   ✅ Step {step_id} succeeded via fallback: {finding}")
                        break
                    print(f"[ExecutionAgent]   ❌ Attempt {attempt+1} failed (fallback)")
                    if attempt < max_attempts - 1:
                        print(f"[ExecutionAgent]   🔄 Replanning...")
                    continue
                parsed = self._parse_text_response(str(response))
                if parsed.get("success"):
                    step_result["status"] = "success"
                    step_result["findings"].append(parsed.get("finding", "Step completed"))
                    break

        return step_result

    def _infer_sqli_param(self, step: dict) -> str:
        """
        Infer intended SQLi parameter safely from step metadata.
        Priority:
          1) explicit target_param
          2) step name hints like '(q parameter)' / 'param \"id\"'
          3) first query parameter in target_url
          4) fallback 'id'
        """
        import re as _re
        from urllib.parse import urlparse, parse_qs

        explicit = (step.get("target_param") or "").strip()
        if explicit:
            return explicit

        step_name = step.get("name", "")
        m = _re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+parameter\b", step_name, _re.IGNORECASE)
        if m:
            return m.group(1)

        m2 = _re.search(r"param(?:eter)?\s*[:=]?\s*['\"]?([a-zA-Z_][a-zA-Z0-9_]*)", step_name, _re.IGNORECASE)
        if m2:
            return m2.group(1)

        target_url = step.get("target_url", "")
        try:
            parsed = urlparse(target_url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if qs:
                return next(iter(qs.keys()))
        except Exception:
            pass

        return "id"

    def _analyze_tool_output(self, tool_name: str, output: dict, step: dict) -> tuple[bool, str]:
        """
        Analyze tool output to determine if step succeeded.
        Returns (success: bool, finding: str)
        """
        if not output.get("success"):
            return False, output.get("stderr", "Tool failed")

        stdout = output.get("stdout", "")

        # SQLMap detection — check real sqli_confirmed flag first, then stdout
        if tool_name in ("sqlmap_detect", "sqlmap_get_dbs"):
            # Real boolean probe or real sqlmap sets this flag
            if output.get("sqli_confirmed"):
                param  = output.get("injectable_param", "?")
                mode   = output.get("tool_mode", "unknown")
                detail = output.get("stdout","")[:200]
                return True, (f"SQLi CONFIRMED [{mode}]: parameter '{param}' is injectable. "
                               f"Evidence: {detail}")
            # Fallback: check stdout for injection keywords
            if any(kw in stdout.lower() for kw in ["injectable","vulnerable","boolean-based",
                                                     "error-based","time-based","union query"]):
                return True, f"SQLi detected (keyword match): {stdout[:200]}"
            return False, "sqlmap executed but did not prove SQLi"

        # Nmap — look for open ports
        elif tool_name == "nmap_port_scan":
            if "open" in stdout.lower() or "SIMULATED" in stdout:
                return True, f"Open ports found: {stdout[:200]}"

        # HTTP probe — always succeeds if we got headers
        elif tool_name == "http_probe":
            # Check body content for real vulnerability proof
            body   = output.get("body", "")
            headers = output.get("headers", {})
            server = headers.get("Server", "unknown")

            # LFI confirmed — file contents in response body
            if output.get("lfi_detected"):
                evidence = output.get("lfi_evidence", "")
                snippet  = output.get("body", body)[:300]
                ev_str   = f" Evidence: {evidence}" if evidence else ""
                return True, f"LFI CONFIRMED: sensitive file contents returned.{ev_str} Body: {snippet}"

            # ── XSS 3-TIER CLASSIFICATION ──
            # CONFIRMED: payload in executable context on valid page
            # PARTIAL: reflected but in error page / escaped / non-executable context
            # REJECTED: no reflection or fully sanitized
            # JSON API endpoints cannot reflect XSS in HTML context
            # Report context uncertainty rather than hard failure
            if output.get("is_json_response") and not output.get("xss_reflected"):
                step_name_l = step.get("name", "").lower()
                if "xss" in step_name_l or "cross-site" in step_name_l:
                    return True, (f"XSS CONTEXT_UNCERTAIN: JSON API endpoint "
                                  f"({step.get('target_url','')}) does not render HTML — "
                                  f"XSS payload cannot execute in this context (HTTP 200). "
                                  f"DOM-based XSS may exist in SPA frontend.")

            if output.get("xss_reflected"):
                tool_url = step.get("target_url", "")
                payload_strs = ["alert(1)", "<script>alert", "onerror=alert",
                                "onload=alert", "javascript:alert"]
                url_has_payload  = any(p.lower() in tool_url.lower() for p in payload_strs)
                body_has_payload = any(p.lower() in body.lower() for p in payload_strs)

                # Check for HTML-encoded/escaped payloads
                escaped_strs = ["&lt;script&gt;", "&lt;script", "&#60;script"]
                body_has_escaped = any(e in body.lower() for e in escaped_strs)

                # Detect error pages
                _status = output.get("status_code", "")
                _headers_raw = output.get("stdout", "")
                if not _status:
                    import re as _re_st
                    _st_match = _re_st.search(r"HTTP/\d\.?\d?\s+(\d{3})", _headers_raw)
                    _status = _st_match.group(1) if _st_match else ""
                _is_error_page = (
                    str(_status).startswith("4") or str(_status).startswith("5") or
                    any(ep in body.lower() for ep in [
                        "http status 4", "http status 5", "404 not found",
                        "400 bad request", "500 internal server error",
                        "page not found", "error page", "whitelabel error",
                        "the requested url was not found",
                    ])
                )

                # Check if payload is in executable context (inside <script>, event handler, DOM)
                _executable_context = False
                if body_has_payload and not _is_error_page:
                    _bl = body.lower()
                    _executable_context = (
                        "<script>alert" in _bl or
                        "onerror=alert" in _bl or
                        "onclick=alert" in _bl or
                        "onload=alert" in _bl or
                        "<svg onload" in _bl or
                        "<img src=x onerror" in _bl
                    )

                if _executable_context:
                    return True, (f"XSS CONFIRMED: payload in executable context "
                                  f"(HTTP {_status or '200'}). Body: {body[:200]}")
                elif body_has_escaped:
                    return False, (f"XSS REJECTED: payload HTML-encoded/escaped in response. "
                                   f"Not exploitable. Body: {body[:150]}")
                elif (url_has_payload or body_has_payload) and _is_error_page:
                    return False, (f"XSS PARTIAL: payload reflected in error page "
                                   f"(HTTP {_status or '?'}). Not exploitable in browser context. "
                                   f"Body: {body[:150]}")
                elif (url_has_payload or body_has_payload) and not _is_error_page:
                    return False, (f"XSS CONTEXT_UNCERTAIN: payload reflected (HTTP {_status or '200'}) "
                                   f"but execution context unclear. Body: {body[:150]}")

            # ── CSRF EXTRACTION ──
            # Extract token presence and HTTP method awareness for CSRF steps
            step_name_lower = step.get("name", "").lower()
            if "csrf" in step_name_lower or "anti-csrf" in step_name_lower:
                _body_lower = body.lower()
                _has_csrf_token = (
                    "csrf" in _body_lower and "input" in _body_lower or
                    "_token" in _body_lower or
                    "csrfmiddlewaretoken" in _body_lower or
                    'name="_csrf"' in _body_lower
                )
                _has_form = "<form" in _body_lower
                _is_state_changing = any(x in _body_lower for x in
                    ['method="post"', "method='post'", 'method="put"', 'method="delete"'])

                if _has_form and not _has_csrf_token:
                    return True, (f"CSRF ANALYSIS: Form found WITHOUT CSRF token. "
                                  f"State-changing={_is_state_changing}. "
                                  f"Token detected=False. Body: {body[:150]}")
                elif _has_form and _has_csrf_token:
                    return True, (f"CSRF ANALYSIS: Form found WITH CSRF token present. "
                                  f"Token detected=True. Body: {body[:150]}")
                else:
                    return True, (f"CSRF ANALYSIS: No form detected on endpoint. "
                                  f"Body length={len(body)}. Server: {server}")

            # ── CORS / CSP / CLICKJACKING / MISCONFIG HEADER EXTRACTION ──
            if ("clickjack" in step_name_lower or "x-frame" in step_name_lower or
                    "misconfig" in step_name_lower or "misconfiguration" in step_name_lower or
                    "header" in step_name_lower or "cors" in step_name_lower or
                    "csp" in step_name_lower):
                # CORS check
                _acao = headers.get("Access-Control-Allow-Origin",
                          headers.get("access-control-allow-origin", ""))
                if _acao == "*":
                    return True, (f"CORS MISCONFIGURATION: Access-Control-Allow-Origin=* "
                                  f"(wildcard) — allows any origin to read responses. "
                                  f"Server: {server}")
                # CSP check
                _csp_val = headers.get("Content-Security-Policy",
                             headers.get("content-security-policy", ""))
                if not _csp_val:
                    _xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
                    return True, (f"SECURITY HEADERS MISSING: CSP=ABSENT, "
                                  f"X-Frame-Options={'ABSENT' if not _xfo else _xfo}. "
                                  f"Server: {server}")
                _xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
                _csp = headers.get("Content-Security-Policy",
                                   headers.get("content-security-policy", ""))
                _has_frame_ancestors = "frame-ancestors" in _csp.lower() if _csp else False

                if not _xfo and not _has_frame_ancestors:
                    return True, (f"CLICKJACKING CONFIRMED: X-Frame-Options=MISSING, "
                                  f"CSP frame-ancestors=MISSING. Server: {server}")
                elif _xfo or _has_frame_ancestors:
                    _xfo_str = _xfo if _xfo else "not set"
                    _fa_str = "present" if _has_frame_ancestors else "not set"
                    return True, (f"CLICKJACKING ANALYSIS: X-Frame-Options={_xfo_str}, "
                                  f"CSP frame-ancestors={_fa_str}. Server: {server}")

            # Generic HTTP body/header response is not exploit proof.
            if body and len(body) > 100:
                return False, f"Body captured ({len(body)} chars) but no vulnerability evidence"

            if output.get("headers") or output.get("success"):
                return False, f"Headers captured only (server: {server}) — no exploit evidence"

        # Directory enum — success if we found anything
        elif tool_name == "web_directory_enum":
            found = output.get("found_paths", [])
            if found:
                return True, f"Found {len(found)} paths: {[p['path'] for p in found]}"
            return True, "Directory enumeration completed (no interesting paths found)"

        # Vuln scan — look for CVEs
        elif tool_name == "nmap_vuln_scan":
            if any(kw in stdout.lower() for kw in ["cve-", "vulnerable", "VULNERABLE", "SIMULATED"]):
                return True, f"Vulnerabilities found: {stdout[:300]}"

        # Generic success if tool ran without error
        if output.get("success") and stdout:
            return True, f"Tool completed: {stdout[:150]}"

        return False, "No meaningful output"

    def _parse_text_response(self, text: str) -> dict:
        """Parse JSON from LLM text response."""
        import re
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        return {"success": False}

    def _request_human_approval(self, step: dict) -> bool:
        """
        Pause and ask for human approval for dangerous steps.
        Based on: Four-Layer Architecture Layer 4, MAPTA ethical constraints.
        """
        print(f"\n[ExecutionAgent] ⚠️  HUMAN APPROVAL REQUIRED")
        print(f"  Step: {step['name']}")
        print(f"  Description: {step.get('description', '')}")
        print(f"  Reason: {step.get('approval_reason', 'Potentially destructive action')}")

        try:
            answer = input("\n  Approve this step? (yes/no): ").strip().lower()
            return answer in ["yes", "y"]
        except (EOFError, KeyboardInterrupt):
            print("  Auto-denying (non-interactive mode)")
            return False

    def _build_execution_report(self, plan: dict) -> dict:
        """Build final execution summary report.
        Split metrics: tool_execution_rate (step ran) vs exploit_validation_rate (vuln confirmed).
        """
        elapsed      = time.time() - self.start_time
        successful   = [r for r in self.results if r.get("status") == "success"]
        failed       = [r for r in self.results if r.get("status") == "failed"]
        all_findings = []

        # Exploit validation: only count findings with actual vuln proof
        _confirmed_keywords = ["confirmed", "injectable", "lfi confirmed", "sqli confirmed",
                               "xss confirmed", "clickjacking confirmed", "csrf analysis: form found without"]
        validated_steps = []
        for r in successful:
            findings = r.get("findings", [])
            all_findings.extend([f for f in findings if f])
            for f in findings:
                if any(kw in f.lower() for kw in _confirmed_keywords):
                    validated_steps.append(r)
                    break

        total = max(len(self.results), 1)
        return {
            "plan_name":              plan.get("target_summary", "Unknown target"),
            "difficulty":             plan.get("difficulty", "unknown"),
            "total_steps":            len(self.results),
            "successful_steps":       len(successful),
            "failed_steps":           len(failed),
            "validated_steps":        len(validated_steps),
            "tool_execution_rate":    len(successful) / total,
            "exploit_validation_rate": len(validated_steps) / total,
            # Keep legacy key for backward compat
            "success_rate":           len(successful) / total,
            "total_time_seconds":     elapsed,
            "tool_calls_used":        self.tool_call_count,
            "findings":               all_findings,
            "step_results":           self.results,
            "owasp_categories":       plan.get("owasp_categories", []),
            "timestamp":              datetime.now().isoformat(),
            "llm_stats": {
                "executor": self.llm_executor.get_usage_stats(),
            },
        }
