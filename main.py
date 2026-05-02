"""
Main Orchestrator — Phase 4 (Critique Agent + Sandbox Validator)

PIPELINE:
  [1] ReconAgent        — Nmap + ZAP + URL discovery
  [2] VulnAnalyst       — MultiVer ensemble confirms vulns
  [3] PlannerAgent      — EKB-aware exploitation plan
  [4] ExecutionAgent    — executes plan step by step
  [4b] CritiqueAgent   — reviews each execution result
                          APPROVED / REJECTED / NEEDS_REFINEMENT
  [4c] SandboxValidator — replays APPROVED findings to verify
                          VERIFIED / UNVERIFIED
  [5] EKB Store         — stores results with critique + sandbox flags
  [6] Report

Usage:
    python main.py --target http://localhost: --mode quick
    python main.py --target http://localhost:9000 --mode full
"""

import json, argparse, os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(override=True)

from agents.recon_agent       import ReconAgent
from agents.vuln_analyst      import VulnAnalystAgent
from agents.planner_agent     import PlannerAgent
from agents.execution_agent   import ExecutionAgent
from agents.critique_agent    import CritiqueAgent
from tools.sandbox_validator  import SandboxValidator
from memory.ekb               import ExperienceKnowledgeBase
from memory.ekb_builder       import EKBBuilder

# ── SIEM Live Event Logger (ELK integration) ─────────────────────────────
import json as _json
from datetime import datetime as _dt
import os as _os

def _elk_log(event_type: str, data: dict) -> None:
    """Write structured event to reports/live_events.ndjson for Filebeat/ELK."""
    try:
        _reports_dir = _os.path.join(_os.path.dirname(__file__), "reports")
        _os.makedirs(_reports_dir, exist_ok=True)
        _log_path = _os.path.join(_reports_dir, "live_events.ndjson")
        record = {"@timestamp": _dt.utcnow().isoformat() + "Z",
                  "event_type": event_type, **data}
        with open(_log_path, "a", encoding="utf-8") as _f:
            _f.write(_json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # never crash the pipeline because of logging
from config.config            import SAFETY, TARGETS, EKB_SETTINGS, ZAP_SETTINGS, PHASE4_SETTINGS, PHASE5_SETTINGS, PHASE6_SETTINGS, PHASE8_SETTINGS
from agents.report_agent      import ReportAgent
from memory.curriculum_scorer import CurriculumScorer


def print_banner():
    print("""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551      AI-POWERED MULTI-AGENT WEB SECURITY TESTER             \u2551
\u2551                                                             \u2551
\u2551                                                             \u2551
\u2551  Pipeline:                                                  \u2551
\u2551    [1] ReconAgent      (Nmap + ZAP + URL discovery)         \u2551
\u2551    [2] VulnAnalyst     (MultiVer ensemble)                  \u2551
\u2551    [3] PlannerAgent    (EKB-aware)                          \u2551
\u2551    [4] ExecutionAgent  (runs the plan)                      \u2551
\u2551   [4b] CritiqueAgent   (APPROVED/REJECTED/NEEDS_REFINEMENT) \u2551
\u2551   [4c] SandboxValidator(VERIFIED/UNVERIFIED replay)         \u2551
\u2551    [5] CurriculumScore → EKB → [6] Report → [7] Benchmark                            \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
""")


def check_api_keys():
    key = os.getenv("GROQ_API_KEY", "")
    if not key or "your_" in key:
        print("Warning: GROQ_API_KEY not set -- demo mode")
        return False
    print("OK: GROQ_API_KEY loaded")
    return True


def save_report(report, output_dir="reports"):
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = (report.get("target_url", "unknown")
              .replace("http://", "").replace("https://", "")
              .replace(":", "_").replace("/", "_"))
    fn = f"{output_dir}/report_{target}_{ts}.json"
    with open(fn, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[Orchestrator] Report saved: {fn}")
    return fn


def run_pipeline(target_url, target_ip="localhost", mode="quick",
                 auto_approve=False, save=True):
    print_banner()
    has_keys = check_api_keys()

    print(f"\nTARGET: {target_url}")
    print(f"MODE:   {mode.upper()}")
    print(f"ZAP:    {ZAP_SETTINGS['host']}:{ZAP_SETTINGS['port']} (scan={ZAP_SETTINGS['scan_type']})")
    print("=" * 62)

    start        = datetime.now()
    final_report = {"target_url": target_url, "target_ip": target_ip}

    ekb = ekb_builder = None
    if EKB_SETTINGS["enabled"] and has_keys:
        print("\nLOADING EKB")
        ekb         = ExperienceKnowledgeBase(ekb_dir=EKB_SETTINGS["ekb_dir"])
        ekb_builder = EKBBuilder(ekb)
        stats       = ekb.get_stats()
        print(f"[EKB] {stats['total_entries']} entries | Types: {list(stats['vuln_type_counts'].keys())}")

    # Step 1
    print("\nSTEP 1: RECONNAISSANCE + ZAP SCAN")
    recon = ReconAgent()
    if mode == "quick" or not has_keys:
        recon_report = recon.run_quick(target_url, target_ip)
    else:
        recon_report = recon.run(target_url, target_ip,
                                  zap_host=ZAP_SETTINGS["host"],
                                  zap_port=ZAP_SETTINGS["port"])
    final_report["recon"] = recon_report
    zap_count = len(recon_report.get("zap_alerts", []))
    print(f"  Risk: {recon_report.get('risk_level','?').upper()} | ZAP Alerts: {zap_count} | Injectable: {len(recon_report.get('injectable_candidates',[]))}")

    # Step 2
    print("\nSTEP 2: VULNERABILITY ANALYSIS")
    if has_keys:
        analyst         = VulnAnalystAgent()
        analysis_report = analyst.analyse(recon_report)
    else:
        analysis_report = {
            "target_url": target_url, "confirmed_count": 0,
            "false_positive_count": 0, "critical_high_count": 0,
            "vuln_summary": [],
            "recon_summary": {
                "injectable_candidates": recon_report.get("injectable_candidates", []),
                "found_paths":           recon_report.get("found_paths", []),
                "web_server":            recon_report.get("web_server", "Unknown"),
            },
        }
    final_report["analysis"] = analysis_report
    print(f"  Confirmed: {analysis_report.get('confirmed_count',0)} | Critical/High: {analysis_report.get('critical_high_count',0)}")
    _elk_log("analysis_complete", {
        "target_url": target_url,
        "confirmed_vulns": analysis_report.get("confirmed_count",0),
        "critical_high": analysis_report.get("critical_high_count",0),
        "false_positives": analysis_report.get("false_positive_count",0),
    })

    # ── Step 2b: Curriculum Difficulty Scoring ────────────────
    print("\nSTEP 2b: CURRICULUM DIFFICULTY SCORING")
    curriculum_summary = {}
    scorer = CurriculumScorer()
    if PHASE5_SETTINGS["curriculum_enabled"] and analysis_report.get("confirmed_count", 0) > 0:
        analysis_report = scorer.score_analysis_report(analysis_report)
        curriculum_summary = analysis_report.get("curriculum_summary", {})
        final_report["curriculum"] = curriculum_summary
        print(f"  Avg difficulty score: {curriculum_summary.get('average_score',0):.3f}")
        print(f"  Recommended start:    {curriculum_summary.get('tier_label','?')}")
    else:
        print("  [Skipped — no confirmed vulns]")

    # Step 3
    print("\nSTEP 3: EXPLOITATION PLANNING")
    if has_keys:
        planner = PlannerAgent(ekb=ekb)
        plan    = planner.create_plan(analysis_report)
        planner.display_plan(plan)
    else:
        plan = {
            "target_summary": f"Demo for {target_url}",
            "owasp_categories": ["A03_Injection"], "difficulty": "simple",
            "attack_vector": "SQL injection", "estimated_success_rate": 0.7, "notes": "Demo",
            "steps": [{"step_id": 1, "name": "HTTP Probe", "description": "Fingerprint",
                        "tool": "http_probe", "target_url": target_url, "target_param": "",
                        "command_hint": f"curl -I {target_url}",
                        "expected_outcome": "Server info", "requires_human_approval": False}],
        }
    final_report["plan"] = plan

    # Step 4
    print("\nSTEP 4: EXECUTION")
    if has_keys:
        executor         = ExecutionAgent()
        execution_report = executor.execute_plan(plan, auto_approve=auto_approve)
    else:
        from tools.tool_wrappers import execute_tool
        results = []
        for step in plan.get("steps", []):
            url = step.get("target_url", "")
            out = execute_tool(step.get("tool", "http_probe"), {"url": url}) if url else {"success": True}
            results.append({
                "step_id": step["step_id"], "name": step["name"],
                "status": "success" if out.get("success") else "failed",
                "findings": [str(out.get("stdout", ""))[:200]],
                "tool_outputs": [{"tool": step.get("tool",""), "args": {"url": url}, "output": out}],
            })
        ok = [r for r in results if r["status"] == "success"]
        execution_report = {
            "total_steps": len(results), "successful_steps": len(ok),
            "success_rate": len(ok) / max(len(results), 1),
            "findings": [f for r in results for f in r.get("findings", []) if f],
            "step_results": results,
        }
    final_report["execution"] = execution_report
    print(f"  Steps: {execution_report.get('total_steps',0)} | Success: {execution_report.get('successful_steps',0)} | Rate: {execution_report.get('success_rate',0)*100:.0f}%")
    # Display queued attack chain steps
    _all_chains = [cs for sr in execution_report.get("step_results",[])
                   for cs in sr.get("chain_steps", [])]
    if _all_chains:
        print(f"  🔗 Attack chain: {len(_all_chains)} follow-up step(s) available:")
        for _cs in _all_chains:
            _flag = "⚠️  HUMAN APPROVAL REQUIRED" if _cs.get("requires_human_approval") else "✅ Auto"
            print(f"     → [{_flag}] {_cs['name']}")

    # Step 4b: Critique
    # NOTE: ESR recording moved to AFTER sandbox so verified_count is available
    print("\nSTEP 4b: CRITIQUE (Co-RedTeam review)")
    critique_report = {}
    if PHASE4_SETTINGS["critique_enabled"] and has_keys:
        critic = CritiqueAgent()
        try:
            critic.ekb = ekb   # inject EKB for HITL learning queries
        except Exception:
            pass
        critique_report = critic.critique(execution_report, analysis_report)
        final_report["critique"] = critique_report
        print(f"  Approved: {critique_report.get('approved_count',0)} | Rejected: {critique_report.get('rejected_count',0)} | Needs Refinement: {critique_report.get('refine_count',0)}")
    for _cs in critique_report.get("critiqued_steps", []):
        _elk_log("critique_verdict", {
            "step_id":    _cs.get("step_id"),
            "step_name":  _cs.get("name"),
            "verdict":    _cs.get("verdict"),
            "confidence": _cs.get("confidence", 0),
            "reason":     _cs.get("reason","")[:120],
            "target_url": target_url,
        })
    else:
        print("  [Skipped]")
        approved = []
        for s in execution_report.get("step_results", []):
            if s.get("status") == "success":
                for to in s.get("tool_outputs", []):
                    approved.append({"step_id": s["step_id"], "step_name": s["name"],
                                     "tool": to.get("tool",""), "args": to.get("args",{}),
                                     "finding": s["findings"][0] if s.get("findings") else "",
                                     "confidence": 0.5})
        critique_report = {"target_url": target_url, "approved_count": len(approved),
                           "rejected_count": 0, "refine_count": 0,
                           "approved_findings": approved, "critiqued_steps": []}
        final_report["critique"] = critique_report

    # Step 4c: Sandbox
    print("\nSTEP 4c: SANDBOX VALIDATION")
    sandbox_report = {}
    if PHASE4_SETTINGS["sandbox_enabled"]:
        validator      = SandboxValidator()
        sandbox_report = validator.validate(critique_report)
        final_report["sandbox"] = sandbox_report
        print(f"  Verified: {sandbox_report.get('verified_count',0)} | Unverified: {sandbox_report.get('unverified_count',0)}")
    for _sv in sandbox_report.get("validations", []):
        _elk_log("sandbox_validation", {
            "step_id":   _sv.get("step_id"),
            "step_name": _sv.get("step_name"),
            "verified":  _sv.get("verified"),
            "method":    _sv.get("method",""),
            "severity":  _sv.get("severity",""),
            "evidence":  str(_sv.get("evidence",""))[:150],
            "location":  _sv.get("location",""),
            "target_url": target_url,
        })
    else:
        print("  [Skipped]")

    # ── HUMAN-IN-THE-LOOP GATE ───────────────────────────────────────────────
    # Teacher guidance: High and Medium verified vulnerabilities require human
    # approval before being stored in EKB and counted in final metrics.
    # This models real-world security workflows where AI finds, human decides.
    # ─────────────────────────────────────────────────────────────────────────
    _sandbox_findings = sandbox_report.get("validations", []) if sandbox_report else []
    _analysis_vulns   = analysis_report.get("vuln_summary", [])
    _severity_map     = {v.get("vuln_type","").lower(): v.get("severity","low")
                         for v in _analysis_vulns}

    if sandbox_report and sandbox_report.get("verified_count", 0) > 0:
        print("\n" + "─"*60)
        print("🔐 HUMAN-IN-THE-LOOP REVIEW")
        print("─"*60)
        _hitl_approved = 0
        _hitl_rejected = 0
        for _sf in _sandbox_findings:
            if not _sf.get("verified"):
                continue
            _vtype    = _sf.get("step_name", "Unknown")
            _evidence = _sf.get("evidence", "")[:200]
            # Severity from step name (which contains XSS/CSRF/LFI etc.)
            _vt_lower = _vtype.lower()
            if any(x in _vt_lower for x in ["sqli","sql","injection","lfi","rce"]):
                _sev = "high"
            elif any(x in _vt_lower for x in ["xss","csrf","idor","xxe"]):
                _sev = "medium"
            else:
                _sev = "low"
            # Only prompt for High/Medium — Low is auto-approved
            if _sev in ("high", "medium"):
                print(f"\n{'═'*50}")
                print(f"  Finding: {_vtype}")
                print(f"  Severity: {_sev.upper()}")
                print(f"  Evidence: {_evidence}")
                print(f"  Target: {target_url}")
                print(f"{'─'*50}")
                try:
                    _decision = input(f"  Approve for EKB + metrics? (y/n/s to skip all): ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    _decision = "y"   # non-interactive mode → auto-approve
                if _decision == "s":
                    print("  [HITL] Skipping remaining reviews — auto-approving all")
                    _hitl_approved += 1
                    break
                elif _decision in ("y", "yes"):
                    _hitl_approved += 1
                    print(f"  [HITL] ✅ APPROVED — will be stored in EKB and counted")
                else:
                    _hitl_rejected += 1
                    print(f"  [HITL] ❌ REJECTED — will not be counted in metrics")
                    # Mark as rejected in sandbox report so ESR doesn't count it
                    _sf["hitl_rejected"] = True
            else:
                _hitl_approved += 1   # Low severity auto-approved
        print(f"\n[HITL] Summary: {_hitl_approved} approved, {_hitl_rejected} rejected")
        print("─"*60)
        # Store human decisions in EKB for future learning
        # This makes HITL a feedback loop — system improves over time
        if ekb and (_hitl_approved > 0 or _hitl_rejected > 0):
            for _sf in _sandbox_findings:
                if not _sf.get("verified"):
                    continue
                _decision = "approved" if not _sf.get("hitl_rejected") else "rejected"
                _step_name = _sf.get("step_name", "Unknown")
                _hitl_entry_id = __import__("uuid").uuid4().hex[:12]
                try:
                    _hitl_entry = {
                        "id":             _hitl_entry_id,
                        "vuln_type":      "HITL_Feedback",
                        "owasp_category": "A00_Human_Review",
                        "difficulty":     0.5,
                        "success":        (_decision == "approved"),
                        "web_server":     "human_review",
                        "retrieval_text": (f"Human review of {_step_name} at {target_url}: "
                                          f"decision={_decision}. "
                                          f"Evidence: {_sf.get('evidence','')[:80]}"),
                        "timestamp":      __import__("datetime").datetime.now().isoformat(),
                        "notes":          f"HITL decision: {_decision} for {_step_name}",
                        "target_url":     target_url,
                        "hitl_decision":  _decision,
                        "step_name":      _step_name,
                    }
                    ekb.store(_hitl_entry)
                    print(f"[HITL] 🧠 Learned: {_step_name} → {_decision} stored in EKB")
                except Exception as _e:
                    pass   # learning is best-effort, never block the pipeline
        # Adjust verified count based on HITL decisions
        _hitl_verified = sum(1 for f in _sandbox_findings
                             if f.get("verified") and not f.get("hitl_rejected"))
        if sandbox_report and _hitl_rejected > 0:
            sandbox_report["verified_count"] = _hitl_verified
    # ─────────────────────────────────────────────────────────────────────────

    # Record ESR now — critique_report and sandbox_report are both fully populated
    # Phase 8 FIX: ESR = verified / confirmed (not approved / confirmed)
    # Each vuln is individually checked against sandbox verification results
    _sandbox_validations = sandbox_report.get("validations", []) if sandbox_report else []
    _sandbox_step_names  = {v.get("step_name", "").lower() for v in _sandbox_validations
                            if v.get("verified") and not v.get("hitl_rejected")}
    for v in analysis_report.get("vuln_summary", []):
        tier      = v.get("curriculum_tier", "simple")
        vtype     = v.get("vuln_type", "Unknown")
        severity  = v.get("severity", "low")
        # Check if THIS specific vuln type was verified by sandbox
        _vt_lower = vtype.lower()
        verified  = any(_vt_lower in sn or sn in _vt_lower for sn in _sandbox_step_names)
        scorer.record_result(vtype, tier, verified, severity)

    # Step 5: EKB
    if ekb and EKB_SETTINGS["enabled"]:
        print("\nSTEP 5: EKB STORE")
        _tag_execution_with_verdicts(execution_report, critique_report, sandbox_report)
        # Fix 4: only store approved findings if ekb_approved_only is True
        # Store if any approved OR needs_refinement findings exist
        has_useful = (critique_report.get("approved_count", 0) > 0 or
                      critique_report.get("refine_count", 0) > 0)
        if PHASE4_SETTINGS.get("ekb_approved_only") and not has_useful:
            print("[EKB] Skipping store — all findings rejected by critique")
            final_report["ekb_stored"] = []
        else:
            stored = ekb_builder.extract_and_store(final_report)
            final_report["ekb_stored"] = stored
            print(f"[EKB] Stored {len(stored)} | Total: {ekb.get_stats()['total_entries']}")

    # Summary
    elapsed = (datetime.now() - start).total_seconds()
    final_report["pipeline_summary"] = {
        "phase": "Phase 7 (Benchmarking)",
        "pipeline_order": "Recon(+ZAP) -> VulnAnalyst -> CurriculumScore -> Planner(EKB) -> Execution -> Critique -> Sandbox -> EKBStore",
        "timestamp": start.isoformat(), "mode": mode,
        "total_time_seconds": elapsed, "zap_alerts": zap_count,
        "zap_source": recon_report.get("zap_source", "none"),
        "urls_discovered": len(recon_report.get("discovered_urls", [])),
        "injectable_candidates": len(recon_report.get("injectable_candidates", [])),
        "confirmed_vulns": analysis_report.get("confirmed_count", 0),
        "critical_high_vulns": analysis_report.get("critical_high_count", 0),
        "execution_steps": execution_report.get("total_steps", 0),
        "execution_success_rate": execution_report.get("success_rate", 0),
        "critique_approved": critique_report.get("approved_count", 0),
        "critique_rejected": critique_report.get("rejected_count", 0),
        "sandbox_verified": sandbox_report.get("verified_count", 0),
        "sandbox_unverified": sandbox_report.get("unverified_count", 0),
        "ekb_entries_stored": len(final_report.get("ekb_stored", [])),
        "curriculum_avg_score": curriculum_summary.get("average_score", 0),
        "curriculum_tier": curriculum_summary.get("recommended_start", "N/A"),
        "esr_this_run": scorer.get_esr(),
    }

    p = final_report["pipeline_summary"]
    print(f"\n{'='*62}")
    print("PHASE 7 PIPELINE COMPLETE")
    print(f"{'='*62}")
    print(f"Target:              {target_url}")
    print(f"Risk Level:          {recon_report.get('risk_level','?').upper()}")
    print(f"ZAP Alerts:          {p['zap_alerts']} (source: {p['zap_source']})")
    print(f"Confirmed Vulns:     {p['confirmed_vulns']}")
    print(f"Critical/High:       {p['critical_high_vulns']}")
    print(f"Execution Steps:     {p['execution_steps']}")
    print(f"Success Rate:        {p['execution_success_rate']*100:.1f}%")
    print(f"Critique Approved:   {p['critique_approved']}")
    print(f"Critique Rejected:   {p['critique_rejected']}")
    print(f"Sandbox Verified:    {p['sandbox_verified']}")
    print(f"Sandbox Unverified:  {p['sandbox_unverified']}")
    print(f"Curriculum Tier:     {p.get('curriculum_tier','N/A').upper()}")
    print(f"Avg Difficulty Score: {p.get('curriculum_avg_score',0):.3f}")
    print(f"EKB Stored:          {p['ekb_entries_stored']} experiences")
    print(f"Total Time:          {p['total_time_seconds']:.1f}s")
    print(f"{'='*62}\n")

    # ── RESEARCH-GRADE METRICS ─────────────────────────────────────
    _steps    = max(p.get("execution_steps", 1), 1)
    _approved = p.get("critique_approved", 0)
    _verified = p.get("sandbox_verified", 0)
    _confirmed = max(p.get("confirmed_vulns", 1), 1)
    _evr  = round((_verified / _steps) * 100, 1)
    _pav  = round((_verified / _approved) * 100, 1) if _approved > 0 else 0.0
    _gap  = _confirmed - _verified
    _fp   = round(p.get("false_positive_rate", 0.0) * 100, 1)
    print("  ── RESEARCH METRICS (EVR / PAV / Gap) ──")
    print(f"  Exploit Validation Rate    (EVR) = {_evr:.1f}%  [verified ÷ executed]")
    print(f"  Precision After Validation (PAV) = {_pav:.1f}%  [verified ÷ approved]")
    print(f"  Pipeline Strictness Gap          = {_gap}    [confirmed − verified]")
    print(f"  False Positive Rate              = {_fp:.1f}%")
    print("  ─────────────────────────────────────────")

    # ── ELK: pipeline complete event ──────────────────────────────────────
    _elk_log("pipeline_complete", {
        "target_url": target_url,
        "confirmed_vulns": p.get("confirmed_vulns", 0),
        "critical_high": p.get("critical_high_vulns", 0),
        "sandbox_verified": p.get("sandbox_verified", 0),
        "critique_approved": p.get("critique_approved", 0),
        "false_positive_rate": p.get("false_positive_rate", 0.0),
        "evr": round(_evr, 1),
        "pav": round(_pav, 1),
        "strictness_gap": _gap,
        "ekb_entries": p.get("ekb_entries_stored", 0),
        "scan_duration_s": round(p.get("total_time_seconds", 0), 1),
        "zap_alerts": p.get("zap_alerts", 0),
        "curriculum_tier": p.get("curriculum_tier", "?"),
        "overall_risk": recon_report.get("risk_level", "?"),
    })


    # ── Step 6: Report Agent ─────────────────────────────────
    report_result = {}
    if PHASE6_SETTINGS["report_enabled"] and has_keys:
        print("\nSTEP 6: REPORT AGENT")
        reporter      = ReportAgent()
        report_result = reporter.generate(
            final_report,
            output_dir=PHASE6_SETTINGS["output_dir"]
        )
        final_report["report"] = report_result
        print(f"  Open in browser: {report_result.get('html_path','')}")
    else:
        print("\nSTEP 6: REPORT AGENT [Skipped — no API keys]")

    # Update pipeline summary with report paths
    final_report["pipeline_summary"]["phase"] = "Phase 6 (Report Agent)"
    final_report["pipeline_summary"]["pipeline_order"] = (
        "Recon(+ZAP) -> VulnAnalyst -> CurriculumScore -> Planner(EKB) "
        "-> Execution -> Critique -> Sandbox -> EKBStore -> ReportAgent"
    )
    if report_result:
        final_report["pipeline_summary"]["html_report"] = report_result.get("html_path","")
        final_report["pipeline_summary"]["elk_report"]  = report_result.get("elk_path","")

    if save:
        save_report(final_report)
    return final_report


def _tag_execution_with_verdicts(execution_report, critique_report, sandbox_report):
    critique_map = {cs["step_id"]: cs for cs in critique_report.get("critiqued_steps", [])}
    sandbox_map  = {v.get("step_id"): v for v in sandbox_report.get("validations", [])}
    for step in execution_report.get("step_results", []):
        sid = step.get("step_id")
        if sid in critique_map:
            step["critique_verdict"]    = critique_map[sid].get("verdict", "UNKNOWN")
            step["critique_confidence"] = critique_map[sid].get("confidence", 0.0)
            step["critique_reason"]     = critique_map[sid].get("reason", "")
        if sid in sandbox_map:
            step["sandbox_verified"] = sandbox_map[sid].get("verified", False)
            step["sandbox_evidence"] = sandbox_map[sid].get("evidence", "")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Web Security Tester -- Phase 7")
    parser.add_argument("--target",  default="http://localhost:9000")
    parser.add_argument("--ip",      default="localhost")
    parser.add_argument("--mode",    choices=["quick", "full"], default="quick")
    parser.add_argument("--auto",    action="store_true")
    parser.add_argument("--no-save", action="store_true")
    args = parser.parse_args()
    run_pipeline(target_url=args.target, target_ip=args.ip, mode=args.mode,
                 auto_approve=args.auto, save=not args.no_save)
