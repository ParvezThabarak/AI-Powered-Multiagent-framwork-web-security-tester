"""
Benchmark Script — Phase 8

PURPOSE:
  Systematically evaluate the AI-Powered Multi-Agent Web Security Tester
  across multiple targets and multiple runs, collecting execution metrics
  for analysis and reporting.

METRICS COLLECTED:
  - ESR (Exploit Success Rate) per difficulty tier
      Simple / Medium / Complex
      ESR = sandbox-verified / ensemble-confirmed
  - False Positive Rate
      ZAP alerts → VulnAnalyst confirmed ratio
  - Critique Approval Rate
      Approved / Total steps critiqued
  - Sandbox Verification Rate
      Verified / Approved findings
  - Time per scan (seconds)
  - EKB growth across runs

OUTPUTS:
  reports/benchmark_<timestamp>.html   — full visual report
  reports/benchmark_<timestamp>.json   — raw data

USAGE:
  python benchmark.py                  — run all targets, 3 runs each
  python benchmark.py --runs 1         — quick single run per target
  python benchmark.py --target 9000    — single target only
"""

import json
import argparse
import time
import sys
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(override=True)
sys.path.insert(0, os.path.dirname(__file__))

from main import run_pipeline
from tools.tool_wrappers import reset_session_cache


# ── Test targets ───────────────────────────────────────────────
DEFAULT_TARGETS = [
    {
        "name":        "DVWA",
        "url":         "http://localhost:9000",
        "description": "Damn Vulnerable Web Application (authenticated, security=Low)",
        "expected_vulns": ["SQLi", "XSS", "LFI", "Misconfiguration"],
    },
    {
        "name":        "Juice Shop",
        "url":         "http://localhost:3000",
        "description": "OWASP Juice Shop (authenticated)",
        "expected_vulns": ["XSS", "SQLi", "Misconfiguration", "CSRF", "Auth_Bypass"],
    },
    {
        "name":        "WebGoat",
        "url":         "http://localhost:9001/WebGoat",
        "description": "OWASP WebGoat (authenticated — requires /WebGoat path)",
        "expected_vulns": ["SQLi", "Misconfiguration"],
    },
    # Port 8084 excluded — 3 targets provides sufficient coverage
    # representing classic (DVWA), modern SPA (Juice Shop), training (WebGoat)
]


def run_benchmark(targets=None, runs_per_target=3, mode="full"):
    """
    Run the full benchmark across all targets.

    targets:           list of target dicts (uses DEFAULT_TARGETS if None)
    runs_per_target:   how many times to run each target (results averaged)
    mode:              "full" or "quick"
    """
    targets = targets or DEFAULT_TARGETS
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path("reports").mkdir(exist_ok=True)

    print("=" * 70)
    print("AI-POWERED MULTI-AGENT WEB SECURITY TESTER — BENCHMARK")
    print("=" * 70)
    print(f"Targets:         {len(targets)}")
    print(f"Runs per target: {runs_per_target}")
    print(f"Mode:            {mode.upper()}")
    print(f"Started:         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    all_results = []

    for t_idx, target in enumerate(targets):
        target_url  = target["url"]
        target_name = target["name"]
        print(f"\n{'─'*70}")
        print(f"TARGET {t_idx+1}/{len(targets)}: {target_name} ({target_url})")
        print(f"{'─'*70}")

        target_runs = []

        # Reset auth session cache so each target gets a fresh login
        reset_session_cache()

        # Brief pause between targets — lets ZAP settle and rate limits recover
        if t_idx > 0:
            print(f"\n[Benchmark] ⏳ Cooling down 15s before next target...")
            import time as _time
            _time.sleep(15)

        for run_idx in range(runs_per_target):
            print(f"\n  Run {run_idx+1}/{runs_per_target}...")
            run_start = time.time()

            try:
                result = run_pipeline(
                    target_url=target_url,
                    target_ip="localhost",
                    mode=mode,
                    auto_approve=True,   # no interactive prompts during benchmark
                    save=False,          # don't save individual reports
                )
                run_time = time.time() - run_start
                p = result.get("pipeline_summary", {})

                run_data = {
                    "run":              run_idx + 1,
                    "success":          True,
                    "time_seconds":     run_time,
                    "zap_alerts":       p.get("zap_alerts", 0),
                    "zap_source":       p.get("zap_source", "none"),
                    "confirmed_vulns":  p.get("confirmed_vulns", 0),
                    "critical_high":    p.get("critical_high_vulns", 0),
                    "false_positives":  result.get("analysis", {}).get("false_positive_count", 0),
                    "execution_steps":  p.get("execution_steps", 0),
                    "critique_approved":p.get("critique_approved", 0),
                    "critique_rejected":p.get("critique_rejected", 0),
                    "sandbox_verified": p.get("sandbox_verified", 0),
                    "ekb_stored":       p.get("ekb_entries_stored", 0),
                    "curriculum_tier":  p.get("curriculum_tier", "N/A"),
                    "avg_difficulty":   p.get("curriculum_avg_score", 0),
                    "esr_this_run":     p.get("esr_this_run", {}),
                }

                print(f"  ✅ Run {run_idx+1} complete: "
                      f"{run_data['confirmed_vulns']} vulns confirmed, "
                      f"{run_data['critique_approved']} approved, "
                      f"{run_time:.0f}s")

            except Exception as e:
                run_time = time.time() - run_start
                print(f"  ❌ Run {run_idx+1} failed: {e}")
                run_data = {
                    "run": run_idx + 1, "success": False,
                    "time_seconds": run_time, "error": str(e),
                    "zap_alerts": 0, "confirmed_vulns": 0,
                    "critique_approved": 0, "sandbox_verified": 0,
                }

            target_runs.append(run_data)

            # Brief pause between runs to respect rate limits
            if run_idx < runs_per_target - 1:
                print(f"  ⏳ Waiting 10s before next run...")
                time.sleep(10)

        # Aggregate results for this target
        aggregated = _aggregate_runs(target, target_runs)
        all_results.append(aggregated)

        # Print per-target summary
        _print_target_summary(aggregated)

    # Final benchmark report
    benchmark_report = _build_benchmark_report(all_results, timestamp, runs_per_target)

    # Save JSON
    json_path = f"reports/benchmark_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(benchmark_report, f, indent=2)
    print(f"\n✅ Benchmark JSON saved: {json_path}")

    # Generate HTML report
    html_path = f"reports/benchmark_{timestamp}.html"
    _generate_html(benchmark_report, html_path)
    print(f"✅ Benchmark HTML saved: {html_path}")

    # Print final summary table
    _print_final_table(benchmark_report)

    return benchmark_report


def _aggregate_runs(target: dict, runs: list) -> dict:
    """Average all metrics across multiple runs for one target."""
    successful = [r for r in runs if r.get("success")]
    if not successful:
        return {
            "target_name": target["name"],
            "target_url":  target["url"],
            "description": target.get("description",""),
            "runs_total":  len(runs),
            "runs_success": 0,
            "error": "All runs failed",
        }

    def avg(key):
        vals = [r.get(key, 0) for r in successful]
        return round(sum(vals) / len(vals), 3)

    def total_zap():
        return max(r.get("zap_alerts", 0) for r in successful)

    # ESR per tier — aggregate across all runs
    esr_data = {}
    for tier in ["simple", "medium", "complex"]:
        attempts  = sum(r.get("esr_this_run", {}).get(tier, {}).get("attempts", 0)  for r in successful)
        successes = sum(r.get("esr_this_run", {}).get(tier, {}).get("successes", 0) for r in successful)
        if attempts > 0:
            esr_data[tier] = {
                "attempts":  attempts,
                "successes": successes,
                "esr":       round(successes / attempts, 3),
                "esr_pct":   f"{successes/attempts*100:.1f}%",
            }

    # False positive rate = FP / (FP + confirmed)
    total_fp        = sum(r.get("false_positives", 0) for r in successful)
    total_confirmed = sum(r.get("confirmed_vulns",  0) for r in successful)
    total_zap_sum   = sum(r.get("zap_alerts",       0) for r in successful)
    fp_rate = round(total_fp / max(total_zap_sum, 1), 3)

    # Critique approval rate
    total_approved = sum(r.get("critique_approved", 0) for r in successful)
    total_steps    = sum(r.get("execution_steps",   0) for r in successful)
    approval_rate  = round(total_approved / max(total_steps, 1), 3)

    return {
        "target_name":      target["name"],
        "target_url":       target["url"],
        "description":      target.get("description",""),
        "expected_vulns":   target.get("expected_vulns",[]),
        "runs_total":       len(runs),
        "runs_success":     len(successful),

        # Averages per run
        "avg_time_seconds":   avg("time_seconds"),
        "avg_zap_alerts":     avg("zap_alerts"),
        "avg_confirmed_vulns":avg("confirmed_vulns"),
        "avg_critique_approved": avg("critique_approved"),
        "avg_sandbox_verified":  avg("sandbox_verified"),
        "avg_ekb_stored":     avg("ekb_stored"),
        "avg_difficulty":     avg("avg_difficulty"),

        # Rates
        "false_positive_rate": fp_rate,
        "fp_rate_pct":         f"{fp_rate*100:.1f}%",
        "critique_approval_rate": approval_rate,
        "approval_rate_pct":   f"{approval_rate*100:.1f}%",

        # ESR per tier
        "esr": esr_data,

        # Raw runs for detail
        "runs": runs,
    }


def _build_benchmark_report(results: list, timestamp: str, runs: int) -> dict:
    """Build the final benchmark report."""

    # Overall ESR across all targets + tiers
    global_esr = {}
    for tier in ["simple", "medium", "complex"]:
        attempts  = sum(r.get("esr", {}).get(tier, {}).get("attempts", 0)  for r in results)
        successes = sum(r.get("esr", {}).get(tier, {}).get("successes", 0) for r in results)
        if attempts > 0:
            global_esr[tier] = {
                "attempts":  attempts,
                "successes": successes,
                "esr":       round(successes / attempts, 3),
                "esr_pct":   f"{successes/attempts*100:.1f}%",
            }

    # Overall averages
    successful = [r for r in results if r.get("runs_success", 0) > 0]
    avg_time   = round(sum(r.get("avg_time_seconds",0) for r in successful) / max(len(successful),1), 1)
    avg_vulns  = round(sum(r.get("avg_confirmed_vulns",0) for r in successful) / max(len(successful),1), 2)
    total_ekb  = sum(r.get("avg_ekb_stored",0) for r in successful)

    return {
        "meta": {
            "timestamp":      timestamp,
            "generated":      datetime.now().isoformat(),
            "runs_per_target": runs,
            "total_targets":  len(results),
            "tool":           "AI-Powered Multi-Agent Web Security Tester",
            "phase":          "Phase 8 — Evaluation & Benchmarking",
        },
        "results":    results,
        "global_esr": global_esr,
        "summary": {
            "avg_time_per_scan_s":    avg_time,
            "avg_confirmed_per_scan": avg_vulns,
            "total_ekb_growth":       total_ekb,
            "targets_tested":         len(results),
        },
    }


def _print_target_summary(agg: dict):
    if not agg:
        return
    runs_s = agg.get("runs_success", 0)
    runs_t = agg.get("runs_total", 0)
    print(f"\n  📊 {agg.get('target_name','?')} Summary:")
    print(f"     Runs:             {runs_s}/{runs_t} successful")
    if runs_s == 0:
        print(f"     ⚠️  No successful runs — pipeline failed for this target")
        return
    print(f"     Avg confirmed:    {agg.get('avg_confirmed_vulns', 0)} vulns/run")
    print(f"     False pos rate:   {agg.get('fp_rate_pct', 'N/A')}")
    print(f"     Critique approved:{agg.get('approval_rate_pct', 'N/A')}")
    avg_t = agg.get('avg_time_seconds', 0)
    print(f"     Avg time:         {avg_t:.0f}s")
    if agg.get("esr"):
        for tier, data in agg["esr"].items():
            if isinstance(data, dict):
                print(f"     ESR {tier:8s}:  {data.get('esr_pct','?')} ({data.get('successes','?')}/{data.get('attempts','?')})")


def _print_final_table(report: dict):
    results = report["results"]
    print(f"\n{'='*70}")
    print("BENCHMARK RESULTS — OBSERVED METRICS")
    print(f"{'='*70}")
    print(f"{'Target':<16} {'Confirmed':>10} {'FP Rate':>9} {'Approved':>10} {'Verified':>10} {'Time(s)':>8}")
    print(f"{'─'*70}")
    for r in results:
        if r.get("runs_success", 0) == 0:
            print(f"{r['target_name']:<16} {'FAILED':>10}")
            continue
        print(f"{r['target_name']:<16} "
              f"{r['avg_confirmed_vulns']:>10.1f} "
              f"{r['fp_rate_pct']:>9} "
              f"{r['approval_rate_pct']:>10} "
              f"{r['avg_sandbox_verified']:>10.1f} "
              f"{r['avg_time_seconds']:>8.0f}")

    print(f"\n{'─'*70}")
    print("Observed ESR by Difficulty Tier:")
    g = report["global_esr"]
    for tier in ["simple","medium","complex"]:
        if tier in g:
            d = g[tier]
            print(f"  {tier.capitalize():8s}: {d['esr_pct']:>6}  "
                  f"({d['successes']}/{d['attempts']} verified/confirmed)")
        else:
            print(f"  {tier.capitalize():8s}: No data")

    s = report["summary"]
    print(f"\n  Avg time/scan:    {s['avg_time_per_scan_s']:.0f}s")
    print(f"  Total EKB growth: {s['total_ekb_growth']:.0f} entries")
    print(f"{'='*70}\n")


def _generate_html(report: dict, path: str):
    """Generate full benchmark HTML report — academic-grade, no external comparisons."""
    results    = report["results"]
    global_esr = report["global_esr"]
    summary    = report["summary"]
    meta       = report["meta"]

    # Target rows
    target_rows = ""
    for r in results:
        if r.get("runs_success", 0) == 0:
            target_rows += f"""
<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb"><strong>{r['target_name']}</strong></td>
  <td colspan="6" style="padding:12px;border-bottom:1px solid #e5e7eb;color:#dc2626">All runs failed</td>
</tr>"""
            continue
        target_rows += f"""
<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb">
    <strong>{r['target_name']}</strong><br>
    <small style="color:#6b7280">{r['target_url']}</small>
  </td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['runs_success']}/{r['runs_total']}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['avg_confirmed_vulns']:.1f}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['fp_rate_pct']}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['approval_rate_pct']}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['avg_sandbox_verified']:.1f}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{r['avg_time_seconds']:.0f}s</td>
</tr>"""

    # ESR rows — observed results only, no external baselines
    esr_rows = ""
    for tier in ["simple", "medium", "complex"]:
        if tier in global_esr:
            d = global_esr[tier]
            our_esr  = d["esr"]
            # Color by absolute ESR quality (green ≥50%, amber ≥25%, red <25%)
            if our_esr >= 0.50:
                color = "#166534"
            elif our_esr >= 0.25:
                color = "#92400e"
            else:
                color = "#991b1b"
            bar_width = min(int(our_esr * 250), 250)
            esr_rows += f"""
<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-transform:capitalize;font-weight:600">{tier}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">
    <strong style="color:{color}">{d['esr_pct']}</strong>
    <div style="background:#e5e7eb;border-radius:4px;height:8px;margin-top:4px">
      <div style="background:{color};width:{bar_width}px;height:8px;border-radius:4px"></div>
    </div>
  </td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{d['successes']}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;text-align:center">{d['attempts']}</td>
</tr>"""
    if not esr_rows:
        esr_rows = '<tr><td colspan="4" style="padding:16px;text-align:center;color:#6b7280">No ESR data collected in this run. Run with mode=full on targets with injectable parameters.</td></tr>'

    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evaluation Report — AI-Powered Multi-Agent Web Security Tester</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827;line-height:1.6}}
.hdr{{background:linear-gradient(135deg,#1e3a5f,#0f2340);color:white;padding:40px 48px}}
.hdr h1{{font-size:28px;font-weight:700;margin-bottom:6px}}
.hdr .sub{{color:#94a3b8;font-size:14px}}
.hdr .meta{{margin-top:20px;display:flex;gap:32px;flex-wrap:wrap}}
.hdr .mi{{font-size:13px}}.hdr .mi strong{{display:block;color:#cbd5e1;font-size:11px;text-transform:uppercase}}
.wrap{{max-width:1200px;margin:0 auto;padding:32px 24px}}
.sec{{background:white;border-radius:12px;padding:28px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.sec h2{{font-size:18px;font-weight:700;color:#1e3a5f;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #e5e7eb}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px}}
.stat{{background:#f8fafc;border-radius:8px;padding:16px;text-align:center;border:1px solid #e5e7eb}}
.stat .n{{font-size:32px;font-weight:800;color:#1e3a5f}}
.stat .l{{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{background:#1e3a5f;color:white;padding:12px;text-align:left;font-weight:600;font-size:13px}}
tr:hover{{background:#f8fafc}}
.note{{background:#f0f9ff;border-left:4px solid #3b82f6;padding:16px;border-radius:0 8px 8px 0;margin-bottom:12px;font-size:14px}}
.limit{{background:#fef3c7;border-left:4px solid #f59e0b;padding:16px;border-radius:0 8px 8px 0;margin-bottom:12px;font-size:14px}}
.defn{{background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px}}
.defn h3{{font-size:14px;font-weight:700;color:#1e3a5f;margin-bottom:4px}}
.defn p{{font-size:13px;color:#374151}}
.ftr{{text-align:center;padding:24px;color:#9ca3af;font-size:13px;border-top:1px solid #e5e7eb}}
</style>
</head>
<body>
<div class="hdr">
  <h1>System Evaluation Report</h1>
  <div class="sub">AI-Powered Multi-Agent Web Security Tester — Prototype Evaluation</div>
  <div class="meta">
    <div class="mi"><strong>Targets Tested</strong>{meta['total_targets']}</div>
    <div class="mi"><strong>Runs per Target</strong>{meta['runs_per_target']}</div>
    <div class="mi"><strong>Generated</strong>{gen_time}</div>
    <div class="mi"><strong>Phase</strong>8 — Evaluation</div>
  </div>
</div>
<div class="wrap">

  <!-- System Execution Summary -->
  <div class="sec"><h2>System Execution Summary</h2>
    <div class="grid">
      <div class="stat"><div class="n">{meta['total_targets']}</div><div class="l">Targets Tested</div></div>
      <div class="stat"><div class="n">{summary['avg_confirmed_per_scan']:.1f}</div><div class="l">Avg Vulns/Scan</div></div>
      <div class="stat"><div class="n">{summary['avg_time_per_scan_s']:.0f}s</div><div class="l">Avg Scan Time</div></div>
      <div class="stat"><div class="n">{summary['total_ekb_growth']:.0f}</div><div class="l">EKB Entries Added</div></div>
    </div>
  </div>

  <!-- Observed Results per Target Environment -->
  <div class="sec"><h2>Observed Results per Target Environment</h2>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Target</th><th style="text-align:center">Runs OK</th>
        <th style="text-align:center">Avg Confirmed</th>
        <th style="text-align:center">FP Rate</th>
        <th style="text-align:center">Approved</th>
        <th style="text-align:center">Verified</th>
        <th style="text-align:center">Avg Time</th>
      </tr></thead>
      <tbody>{target_rows}</tbody>
    </table>
    </div>
  </div>

  <!-- Observed ESR by Difficulty Tier -->
  <div class="sec"><h2>Observed ESR by Difficulty Tier</h2>
    <p style="color:#6b7280;font-size:13px;margin-bottom:16px">
      Exploit Success Rate measured as the ratio of sandbox-verified vulnerabilities
      to ensemble-confirmed vulnerabilities, grouped by CurriculumPT difficulty tier
      (D&nbsp;=&nbsp;0.3&middot;AC&nbsp;+&nbsp;0.2&middot;UI&nbsp;+&nbsp;0.2&middot;PR&nbsp;+&nbsp;0.3&middot;ES).
    </p>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Difficulty Tier</th>
        <th style="text-align:center">Observed ESR</th>
        <th style="text-align:center">Verified</th>
        <th style="text-align:center">Confirmed</th>
      </tr></thead>
      <tbody>{esr_rows}</tbody>
    </table>
    </div>
  </div>

  <!-- Metric Definitions -->
  <div class="sec"><h2>Metric Interpretation</h2>
    <p style="color:#6b7280;font-size:13px;margin-bottom:16px">
      The following definitions apply to all metrics reported in this evaluation.
    </p>
    <div class="defn">
      <h3>Exploit Success Rate (ESR)</h3>
      <p>ESR = Verified / Confirmed. Measures the proportion of ensemble-confirmed
         vulnerabilities that were subsequently validated through sandbox exploitation.
         A vulnerability is <em>confirmed</em> when the multi-agent ensemble reaches
         majority consensus. It is <em>verified</em> when the Sandbox Validator
         independently reproduces the exploit with observable evidence.</p>
    </div>
    <div class="defn">
      <h3>False Positive Rate (FPR)</h3>
      <p>FPR = False Positives / Total ZAP Alerts. The ratio of ZAP-reported alerts
         that the VulnAnalyst ensemble rejected as non-exploitable. A low FPR indicates
         effective filtering of scanner noise.</p>
    </div>
    <div class="defn">
      <h3>Critique Approval Rate</h3>
      <p>The proportion of executed exploitation steps that survived the Critique Agent's
         evidence review. Steps are rejected if they lack sufficient proof of exploitation
         (e.g., payload reflection in error pages, status-code-only evidence).</p>
    </div>
    <div class="defn">
      <h3>Difficulty Tiers</h3>
      <p>Vulnerabilities are scored using a weighted formula:
         D&nbsp;=&nbsp;0.3&middot;AC&nbsp;+&nbsp;0.2&middot;UI&nbsp;+&nbsp;0.2&middot;PR&nbsp;+&nbsp;0.3&middot;ES.
         <strong>Simple</strong>&nbsp;(D&lt;0.30): basic injections, missing headers.
         <strong>Medium</strong>&nbsp;(0.30&le;D&lt;0.60): LFI, stored XSS, auth bypass.
         <strong>Complex</strong>&nbsp;(D&ge;0.60): RCE, SSRF, chained attacks.</p>
    </div>
  </div>

  <!-- Limitations -->
  <div class="sec"><h2>Limitations</h2>
    <p style="color:#6b7280;font-size:13px;margin-bottom:16px">
      The following limitations should be considered when interpreting these results.
    </p>
    <div class="limit">
      <strong>Limited target diversity:</strong> Evaluation was conducted on {meta['total_targets']}
      intentionally vulnerable web applications (DVWA, Juice Shop, WebGoat). Results may not
      generalise to production systems or applications with custom security controls.
    </div>
    <div class="limit">
      <strong>Single-environment execution:</strong> All targets were hosted locally on the same
      machine. Network latency, WAF interference, and real-world infrastructure variability
      are not represented.
    </div>
    <div class="limit">
      <strong>Limited statistical validation:</strong> With {meta['runs_per_target']} run(s) per
      target, results may exhibit variance. A larger sample size would be required for
      statistically significant conclusions.
    </div>
    <div class="limit">
      <strong>Black-box scope only:</strong> The system performs black-box testing via HTTP
      probing and tool-based exploitation. It does not perform source-code analysis,
      which limits detection of second-order and logic vulnerabilities.
    </div>
    <div class="limit">
      <strong>LLM non-determinism:</strong> Results may vary between runs due to the
      stochastic nature of large language model inference, even at low temperature settings.
    </div>
  </div>

  <!-- Future Work -->
  <div class="sec"><h2>Future Work</h2>
    <div class="note">
      <strong>Multi-run statistical analysis:</strong> Conduct 10+ runs per target to compute
      confidence intervals and assess result stability across LLM inference variance.
    </div>
    <div class="note">
      <strong>Expanded target coverage:</strong> Evaluate against additional vulnerable
      applications (e.g., HackTheBox, VulnHub, XBOW benchmark) and real-world CTF environments
      to assess generalisability.
    </div>
    <div class="note">
      <strong>Adaptive learning evaluation:</strong> Measure EKB hit rate and ESR improvement
      across sequential runs on the same target to quantify the system's progressive
      learning capability.
    </div>
    <div class="note">
      <strong>Ablation study:</strong> Systematically disable individual components
      (parallel sampling, Plan B, critique gate, EKB) to isolate each component's
      contribution to overall system performance.
    </div>
  </div>

  <div class="ftr">
    AI-Powered Multi-Agent Web Security Tester — System Evaluation Report<br>
    SRM Institute of Science and Technology &middot; Department of Computing Technologies<br>
    Generated: {gen_time}
  </div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 8 — Benchmark")
    parser.add_argument("--runs",   type=int, default=3,
                        help="Runs per target (default: 3)")
    parser.add_argument("--mode",   choices=["full","quick"], default="full",
                        help="Scan mode (default: full)")
    parser.add_argument("--target", type=str, default=None,
                        help="Run only this target port e.g. 9000")
    args = parser.parse_args()

    targets = DEFAULT_TARGETS
    if args.target:
        targets = [t for t in DEFAULT_TARGETS if args.target in t["url"]]
        if not targets:
            print(f"No target found for: {args.target}")
            sys.exit(1)

    run_benchmark(
        targets=targets,
        runs_per_target=args.runs,
        mode=args.mode,
    )
