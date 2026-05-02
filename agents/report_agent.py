"""
Report Agent — Phase 8

ARCHITECTURE ROLE:
  Step 6 of 7 in the pipeline.
  Receives the complete final_report and generates:
    1. HTML report  — self-contained, opens in browser
    2. ELK JSON     — Elasticsearch-ready, flat fields for Kibana

  Uses LLM to write executive summary and remediation advice.

Based on:
  PENTEST-AI (IEEE CSR 2024): RA agent maps findings to MITRE ATT&CK
  IEEE Web Collab (Telkom 2025): ELK Stack reporting, 41 vulns reported
  CurriculumPT (2025): difficulty scores per finding in report
  MAPTA (UCL 2025): structured JSON with cost metrics
"""

import json
from datetime import datetime
from pathlib import Path
from agents.llm_client import LLMClient

MITRE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1189": "Drive-by Compromise",
    "T1083": "File and Directory Discovery",
    "T1078": "Valid Accounts",
    "T1090": "Proxy",
    "T1592": "Gather Victim Host Information",
    "T1595": "Active Scanning",
    "T1071": "Application Layer Protocol",
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
}

OWASP_REMEDIATION = {
    "A01_Broken_Access_Control":    "Enforce server-side access controls. Deny by default. Log all failures.",
    "A02_Cryptographic_Failures":   "Use strong encryption (AES-256, TLS 1.3). Never store plaintext credentials.",
    "A03_Injection":                "Use parameterised queries and prepared statements. Validate all input server-side.",
    "A04_Insecure_Design":          "Apply threat modelling during design. Use secure design patterns.",
    "A05_Security_Misconfiguration":"Harden server configuration. Remove default credentials. Disable unnecessary features.",
    "A06_Vulnerable_Components":    "Keep all dependencies updated. Subscribe to CVE alerts for used libraries.",
    "A07_Auth_Failures":            "Implement MFA. Use secure session management. Enforce strong password policies.",
    "A08_Software_Data_Integrity":  "Verify checksums. Use signed packages. Implement integrity checks.",
    "A09_Logging_Failures":         "Log all auth events and failures. Alert on anomalies. Protect log files.",
    "A10_SSRF":                     "Validate all user-supplied URLs. Use allowlists for outbound requests.",
    "Unknown":                      "Review application security controls for this vulnerability class.",
}

REPORT_SYSTEM_PROMPT = """You are a professional penetration testing report writer.
Write a concise executive summary for a security assessment.
Audience: non-technical manager or developer team lead.

Based on the findings, write:
1. Executive Summary (2-3 sentences) — what was tested, what was found, overall risk
2. Key Findings (max 4 bullet points) — most important vulns in plain English
3. Immediate Actions (max 3 bullet points) — what to fix first

Keep language clear, professional, and actionable. No markdown headers."""


class ReportAgent:
    """
    Report Agent — Step 6 of the pipeline.
    Generates HTML and ELK-ready JSON from the complete pipeline output.
    """

    def __init__(self):
        self.llm = LLMClient("reporter")

    def generate(self, final_report: dict, output_dir: str = "reports") -> dict:
        Path(output_dir).mkdir(exist_ok=True)

        target_url  = final_report.get("target_url", "unknown")
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = (target_url.replace("http://", "").replace("https://", "")
                       .replace(":", "_").replace("/", "_"))

        print(f"\n[ReportAgent] Generating security report...")
        print(f"[ReportAgent] Target: {target_url}")
        print("-" * 50)

        data = self._collect(final_report)
        data["executive_summary"] = self._executive_summary(data)
        print(f"[ReportAgent] Executive summary generated")

        html_path = f"{output_dir}/report_{safe_target}_{timestamp}.html"
        elk_path  = f"{output_dir}/report_{safe_target}_{timestamp}_elk.json"

        self._html(data, html_path)
        self._elk(data, elk_path)

        print(f"[ReportAgent] HTML report saved: {html_path}")
        print(f"[ReportAgent] ELK JSON saved:   {elk_path}")
        print(f"[ReportAgent] Validated vulns:  {data['validated_count']}")
        print(f"[ReportAgent] Overall risk:     {data['overall_risk'].upper()}")
        print(f"[ReportAgent] MITRE techniques: {len(data['mitre_techniques'])}")

        return {
            "html_path":        html_path,
            "elk_path":         elk_path,
            "validated_count":  data["validated_count"],
            "overall_risk":     data["overall_risk"],
            "mitre_techniques": data["mitre_techniques"],
            "executive_summary": data["executive_summary"],
        }

    def _collect(self, r: dict) -> dict:
        p  = r.get("pipeline_summary", {})
        a  = r.get("analysis", {})
        rc = r.get("recon", {})
        cu = r.get("curriculum", {})
        ex = r.get("execution", {})
        cr = r.get("critique", {})
        sb = r.get("sandbox", {})

        # Detected vulns from VulnAnalyst
        detected_vulns = a.get("vuln_summary", [])
        
        # We need to map execution/critique/sandbox results to 3 buckets
        validated_vulns = []
        potential_vulns = []
        rejected_findings = []
        
        # 1. Validated (Sandbox VERIFIED)
        for val in sb.get("validations", []):
            if val.get("verified") and not val.get("hitl_rejected", False):
                validated_vulns.append(val)
            else:
                potential_vulns.append(val) # Unverified by sandbox becomes potential
                
        # 2. Add Critique NEEDS_REFINEMENT back to potential 
        #    Add REJECTED to rejected_findings
        for c in cr.get("critiqued_steps", []):
            if c.get("verdict") == "NEEDS_REFINEMENT":
                potential_vulns.append(c)
            elif c.get("verdict") == "REJECTED":
                rejected_findings.append(c)
                
        # In case execution failed completely, add to rejected
        for s in ex.get("step_results", []):
            if s.get("status") == "failed":
                rejected_findings.append({
                    "step_name": s.get("name", "Unknown Step"),
                    "verdict": "REJECTED",
                    "reason": "Tool execution failed",
                    "evidence": s.get("evidence", "No evidence"),
                    "tool": "unknown"
                })

        # Calculate Risk based ONLY on validated
        risk = "low"
        crith_count = 0
        mitre_techs = set()
        
        # Reconstruct severity and OWASP metadata for Validated
        for v in validated_vulns:
            sname = v.get("step_name", "").lower()
            orig = str(v.get("original_finding", "")).lower()
            
            # Map back to original detected
            mapped_vuln = next((d for d in detected_vulns if d.get("vuln_type", "").lower() in sname or sname in d.get("vuln_type", "").lower()), {})
            
            sev = mapped_vuln.get("severity", "low")
            if sev == "low":
                if any(x in sname for x in ["sqli","sql","injection","lfi","rce"]) or any(x in orig for x in ["sqli","sql","lfi","rce"]):
                   sev = "high"
                elif any(x in sname for x in ["xss","csrf","idor","xxe","clickjack","misconfig"]) or any(x in orig for x in ["xss","csrf","clickjack"]):
                   sev = "medium"
               
            v["severity"] = sev
            v["vuln_type"] = v.get("step_name", "Unknown Finding")
            v["owasp"] = mapped_vuln.get("owasp", "Unknown")
            tid = mapped_vuln.get("mitre_technique", "")
            if tid: mitre_techs.add(tid)
            v["mitre_technique"] = tid
            v["location"] = v.get("args", {}).get("url", "unknown endpoint")
            
            if sev == "critical": 
                risk = "critical"
                crith_count += 1
            elif sev == "high":   
                risk = "high"
                crith_count += 1
            elif sev == "medium" and risk == "low": 
                risk = "medium"
                
        if not validated_vulns:
            risk = "low"

        # Calculate Validation Rate
        total_executed = p.get("execution_steps", 0)
        validation_rate = (len(validated_vulns) / total_executed) if total_executed > 0 else 0.0

        return {
            "target_url": r.get("target_url",""), "target_ip": r.get("target_ip","localhost"),
            "web_server": rc.get("web_server","Unknown"),
            "scan_timestamp": p.get("timestamp", datetime.now().isoformat()),
            "scan_mode": p.get("mode","full"), "total_time_seconds": p.get("total_time_seconds",0),
            
            # Metrics
            "zap_alerts": p.get("zap_alerts",0), "zap_source": p.get("zap_source","none"),
            "urls_discovered": p.get("urls_discovered",0),
            "candidates_analyzed": a.get("confirmed_count",0),
            "false_positive_count": a.get("false_positive_count",0),
            
            # Sub-Findings Sets
            "validated_vulns": validated_vulns,
            "validated_count": len(validated_vulns),
            "potential_vulns": potential_vulns,
            "rejected_findings": rejected_findings,
            
            "critical_high_count": crith_count,
            "overall_risk": risk, "mitre_techniques": list(mitre_techs),
            
            # Curriculum
            "curriculum_tier": cu.get("recommended_start","N/A"),
            "avg_difficulty": cu.get("average_score",0),
            
            # Pipeline stats
            "execution_steps": total_executed,
            "tool_execution_rate": p.get("tool_execution_rate", 0),
            "validation_rate": validation_rate,
            "critique_approved": p.get("critique_approved",0),
            "critique_rejected": p.get("critique_rejected",0),
            "ekb_stored": p.get("ekb_entries_stored",0),
        }

    def _executive_summary(self, d: dict) -> str:
        prompt = (f"Target: {d['target_url']}\nServer: {d['web_server']}\n"
                  f"Risk: {d['overall_risk'].upper()}\nTotal Alerts (incl Info): {d['zap_alerts']}\n"
                  f"Validated Vulnerabilities: {d['validated_count']}\n"
                  f"Critical/High Validated: {d['critical_high_count']}\n\n")
                  
        if d["validated_count"] > 0:
            vlist = "\n".join(
                f"- {v.get('vuln_type','?')} [{v.get('severity','?').upper()}] "
                f"at {v.get('location','?')} (Evidence based on Sandbox Verification)"
                for v in d["validated_vulns"]
            )
            prompt += f"Validated Vulnerabilities:\n{vlist}\n\nMITRE techniques: {', '.join(d['mitre_techniques']) or 'None'}"
        else:
            prompt += "No vulnerabilities could be validated in the sandbox environment. All alerts were classified as false positives, prevented from exploitation, or rejected by critique."

        try:
            return str(self.llm.chat([
                {"role":"system","content":REPORT_SYSTEM_PROMPT},
                {"role":"user","content":prompt}
            ])).strip()
        except Exception as e:
            print(f"[ReportAgent] LLM error: {e}")
            n = d["validated_count"]
            return (f"Security assessment of {d['target_url']} completed. Zero vulnerabilities were validated in the sandbox, resulting in a {d['overall_risk'].upper()} risk profile."
                    if n == 0 else
                    f"Assessment of {d['target_url']} identified {n} mathematically validated vulnerability(ies) "
                    f"with an overall risk of {d['overall_risk'].upper()}. Immediate remediation is recommended.")

    def _enrich(self, vulns: list) -> list:
        out = []
        for v in vulns:
            tid  = v.get("mitre_technique","")
            owasp = v.get("owasp","Unknown")
            e = dict(v)
            e["mitre_full_name"]  = v.get("mitre_name") or MITRE_NAMES.get(tid,"Unknown")
            e["remediation_text"] = v.get("remediation") or OWASP_REMEDIATION.get(owasp, OWASP_REMEDIATION["Unknown"])
            e["severity_color"]   = {"critical":"#dc2626","high":"#ea580c","medium":"#d97706",
                                      "low":"#65a30d","informational":"#6b7280"}.get(v.get("severity","low"),"#6b7280")
            out.append(e)
        return out

    def _html(self, d: dict, path: str):
        rc = {"critical":"#dc2626","high":"#ea580c","medium":"#d97706","low":"#65a30d"}
        risk_color = rc.get(d["overall_risk"],"#6b7280")
        
        d["validated_vulns"] = self._enrich(d["validated_vulns"])

        # 1. Validated Section
        rows_val = ""
        evidence_blocks = ""
        for i,v in enumerate(d.get("validated_vulns",[]),1):
            sc = v.get("severity_color","#6b7280")
            rows_val += f"""
<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-weight:600">{i}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb"><strong>{v.get('vuln_type','?')}</strong><br>
    <small style="color:#6b7280">{v.get('location','')}</small></td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb">
    <span style="background:{sc};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">
      {v.get('severity','?').upper()}</span></td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb">{v.get('owasp','?')}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb">
    <code style="font-size:12px">{v.get('mitre_technique','')}</code><br>
    <small>{v.get('mitre_full_name','')}</small></td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-size:13px">{v.get('remediation_text','')}</td>
</tr>"""
            args_str = json.dumps(v.get('args', {}), indent=2)
            evidence_str = str(v.get('evidence',''))
            evidence_blocks += f"""
<div style="background:#f8fafc; border:1px solid #e2e8f0; border-left:4px solid {sc}; border-radius:6px; padding:16px; margin-bottom:16px;">
  <h4 style="margin-bottom:8px; color:#1e293b;">{i}. {v.get('vuln_type','?')} — {v.get('tool','?')}</h4>
  <p style="font-size:13px; color:#475569; margin-bottom:4px;"><strong>Target:</strong> <code style="background:#e2e8f0; padding:2px 4px; border-radius:3px;">{v.get('location','?')}</code></p>
  <p style="font-size:13px; color:#475569; margin-bottom:8px;"><strong>Payload/Args:</strong> <pre style="background:#f1f5f9; padding:8px; border-radius:4px; font-size:12px; overflow-x:auto;">{args_str}</pre></p>
  <p style="font-size:13px; color:#475569;"><strong>Validation Evidence:</strong> <pre style="background:#1e293b; color:#10b981; padding:8px; border-radius:4px; font-size:12px; overflow-x:auto;">{evidence_str}</pre></p>
</div>"""

        if not rows_val:
            rows_val = '<tr><td colspan="6" style="padding:20px;text-align:center;color:#6b7280">No vulnerabilities successfully validated. System effectively mitigated false positives.</td></tr>'
            evidence_blocks = '<p style="color:#6b7280; font-size:14px;">No evidence available.</p>'

        # 2. Potential Section
        rows_pot = ""
        for i,v in enumerate(d.get("potential_vulns",[]),1):
            nm = v.get("step_name", v.get("name", "Unknown Finding"))
            rs = v.get("evidence", v.get("reason", "Needs refinement context"))
            rows_pot += f"""<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-weight:600;color:#92400e;">{i}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb"><strong>{nm}</strong></td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#475569">{rs}</td>
</tr>"""
        if not rows_pot:
            rows_pot = '<tr><td colspan="3" style="padding:20px;text-align:center;color:#6b7280">No potential vulnerabilities buffered.</td></tr>'

        # 3. Rejected Section
        rows_rej = ""
        for i,v in enumerate(d.get("rejected_findings",[]),1):
            nm = v.get("name", v.get("step_name", "Unknown Finding"))
            rs = v.get("reason", v.get("evidence", "Insufficient evidence"))
            rows_rej += f"""<tr>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-weight:600;color:#991b1b;">{i}</td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb"><strike><strong>{nm}</strong></strike></td>
  <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#64748b">{rs}</td>
</tr>"""
        if not rows_rej:
            rows_rej = '<tr><td colspan="3" style="padding:20px;text-align:center;color:#6b7280">No findings rejected.</td></tr>'


        mitre_html = "".join(
            f'<span style="background:#eff6ff;color:#1d4ed8;padding:4px 10px;border-radius:4px;margin:3px;display:inline-block;font-size:13px">'
            f'<strong>{tid}</strong> — {MITRE_NAMES.get(tid,"")}</span>'
            for tid in d.get("mitre_techniques",[])
        ) or '<span style="color:#6b7280">No techniques successfully mapped</span>'

        exec_html = d.get("executive_summary","").replace("\n","<br>")
        scan_dt   = d.get("scan_timestamp","")[:19].replace("T"," ")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {d['target_url']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827;line-height:1.6}}
.hdr{{background:linear-gradient(135deg,#1e3a5f,#0f2340);color:white;padding:40px 48px}}
.hdr h1{{font-size:28px;font-weight:700;margin-bottom:6px}}
.hdr .sub{{color:#94a3b8;font-size:14px}}
.hdr .meta{{margin-top:20px;display:flex;gap:32px;flex-wrap:wrap}}
.hdr .mi{{font-size:13px}}.hdr .mi strong{{display:block;color:#cbd5e1;font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.wrap{{max-width:1200px;margin:0 auto;padding:32px 24px}}
.rbadge{{display:inline-flex;align-items:center;gap:8px;background:{risk_color}20;border:2px solid {risk_color};color:{risk_color};padding:8px 20px;border-radius:8px;font-weight:700;font-size:18px;margin-bottom:24px}}
.sec{{background:white;border-radius:12px;padding:28px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.sec h2{{font-size:18px;font-weight:700;color:#1e3a5f;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #e5e7eb}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px}}
.stat{{background:#f8fafc;border-radius:8px;padding:16px;text-align:center;border:1px solid #e5e7eb}}
.stat .n{{font-size:32px;font-weight:800;color:#1e3a5f}}
.stat .l{{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}}
.exec{{background:#f0f9ff;border-left:4px solid #0284c7;padding:20px 24px;border-radius:0 8px 8px 0;font-size:15px;line-height:1.8;color:#0c4a6e}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{background:#1e3a5f;color:white;padding:12px;text-align:left;font-weight:600;font-size:13px}}
tr:hover{{background:#f8fafc}}
.ps{{display:flex;align-items:center;gap:12px;padding:12px;border-radius:8px;background:#f8fafc;margin-bottom:8px;border:1px solid #e5e7eb}}
.si{{width:36px;height:36px;border-radius:50%;background:#1e3a5f;color:white;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0}}
.sn{{font-weight:600;font-size:14px}}.sd{{font-size:13px;color:#6b7280}}
.ftr{{text-align:center;padding:24px;color:#9ca3af;font-size:13px;border-top:1px solid #e5e7eb;margin-top:16px}}
</style>
</head>
<body>
<div class="hdr">
  <h1>Security Assessment Report</h1>
  <div class="sub">AI-Powered Multi-Agent Web Security Tester — Validation-Driven Output</div>
  <div class="meta">
    <div class="mi"><strong>Target</strong>{d['target_url']}</div>
    <div class="mi"><strong>Web Server</strong>{d['web_server']}</div>
    <div class="mi"><strong>Scan Date</strong>{scan_dt}</div>
    <div class="mi"><strong>Mode</strong>{d['scan_mode'].upper()}</div>
    <div class="mi"><strong>Duration</strong>{d['total_time_seconds']:.0f}s</div>
  </div>
</div>
<div class="wrap">
  <div class="rbadge">Overall Risk: {d['overall_risk'].upper()}</div>
  <div class="sec"><h2>Assessment Summary</h2>
    <div class="grid">
      <div class="stat"><div class="n">{d['zap_alerts']}</div><div class="l">Raw Alerts</div></div>
      <div class="stat"><div class="n">{d['candidates_analyzed']}</div><div class="l">Candidates Analyzed</div></div>
      <div class="stat"><div class="n" style="color:{risk_color}">{d['validated_count']}</div><div class="l">Validated Vulns</div></div>
      <div class="stat"><div class="n" style="color:#059669">{d['validation_rate']*100:.0f}%</div><div class="l">Validation Rate</div></div>
    </div>
  </div>
  <div class="sec"><h2>Executive Summary</h2><div class="exec">{exec_html}</div></div>
  
  <div class="sec"><h2>1. Validated Vulnerabilities ({d['validated_count']})</h2>
    <p style="font-size:13px; color:#475569; margin-bottom:12px;">These vulnerabilities have been cryptographically or logically verified via mathematical sandbox exploitation.</p>
    <div style="overflow-x:auto; margin-bottom:24px;">
    <table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>OWASP</th><th>MITRE ATT&CK</th><th>Remediation</th></tr></thead>
    <tbody>{rows_val}</tbody></table></div>
    <h3 style="font-size:16px; margin-bottom:12px; color:#1e3a5f;">Validation Evidence</h3>
    {evidence_blocks}
  </div>

  <div class="sec" style="opacity: 0.95;"><h2>2. Potential Vulnerabilities (Needs Refinement) ({len(d.get('potential_vulns',[]))})</h2>
    <p style="font-size:13px; color:#475569; margin-bottom:12px;">These findings returned partial validation evidence but lacked concrete proof for automatic confirmation.</p>
    <div style="overflow-x:auto">
    <table><thead><tr><th>#</th><th>Vulnerability Type</th><th>Limitation / Missing Context</th></tr></thead>
    <tbody>{rows_pot}</tbody></table></div>
  </div>

  <div class="sec" style="opacity: 0.8;"><h2>3. Rejected Findings (False Positives Mitigated) ({len(d.get('rejected_findings',[]))})</h2>
    <p style="font-size:13px; color:#475569; margin-bottom:12px;">These findings were flagged by early detection but correctly rejected by explicit security logic checks.</p>
    <div style="overflow-x:auto">
    <table style="background: #fffafa;"><thead><tr><th>#</th><th>Analyzed Target</th><th>Rejection Justification</th></tr></thead>
    <tbody>{rows_rej}</tbody></table></div>
  </div>

  <div class="sec"><h2>MITRE ATT&CK Techniques</h2>
    <div style="padding:8px 0">{mitre_html}</div>
    <p style="margin-top:16px;font-size:13px;color:#6b7280">Reference: <a href="https://attack.mitre.org" style="color:#1d4ed8">https://attack.mitre.org</a></p>
  </div>
  
  <div class="sec"><h2>Pipeline Execution Context</h2>
    <div class="ps"><div class="si">1</div><div><div class="sn">Reconnaissance Agent</div><div class="sd">ZAP {d['zap_alerts']} alerts ({d['zap_source']}) · {d['urls_discovered']} URLs</div></div></div>
    <div class="ps"><div class="si">2</div><div><div class="sn">Vulnerability Analyst (MultiVer 4-Agent)</div><div class="sd">{d['candidates_analyzed']} Candidates Assessed · {d['false_positive_count']} FP filtered early</div></div></div>
    <div class="ps"><div class="si">3</div><div><div class="sn">Exploit Planner (EKB-Aware)</div><div class="sd">{d['execution_steps']} steps planned</div></div></div>
    <div class="ps"><div class="si">4</div><div><div class="sn">Execution Agent</div><div class="sd">{d['execution_steps']} steps executed · Tool Execution Rate: {d['tool_execution_rate']*100:.0f}%</div></div></div>
    <div class="ps"><div class="si">4b</div><div><div class="sn">Critique Agent (Co-RedTeam)</div><div class="sd">Approved: {d['critique_approved']} · Rejected: {d['critique_rejected']}</div></div></div>
    <div class="ps"><div class="si">4c</div><div><div class="sn">Sandbox Validator</div><div class="sd">Validated: {d['validated_count']} · Validation Rate: {d['validation_rate']*100:.0f}%</div></div></div>
    <div class="ps"><div class="si">5</div><div><div class="sn">EKB Memory (FAISS)</div><div class="sd">{d['ekb_stored']} experiences stored</div></div></div>
    <div class="ps" style="background:#f0fdf4;border-color:#86efac"><div class="si" style="background:#166534">6</div>
      <div><div class="sn">Report Agent (This Report)</div><div class="sd">HTML + ELK JSON · Strict Validation Mode</div></div></div>
  </div>
  <div class="ftr">
    AI-Powered Multi-Agent Web Security Tester — Validation-Driven Report<br>
    SRM Institute of Science and Technology &middot; Department of Computing Technologies<br>
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  </div>
</div>
</body>
</html>"""
        with open(path,"w",encoding="utf-8") as f:
            f.write(html)

    def _elk(self, d: dict, path: str):
        doc = {
            "@timestamp": d.get("scan_timestamp", datetime.now().isoformat()),
            "@version": "1", "type": "pentest_report",
            "target.url": d["target_url"], "target.ip": d["target_ip"],
            "target.web_server": d["web_server"],
            "scan.mode": d["scan_mode"], "scan.duration_s": d["total_time_seconds"],
            "scan.zap_alerts": d["zap_alerts"], "scan.zap_source": d["zap_source"],
            "scan.urls_found": d["urls_discovered"],
            "scan.candidates_analyzed": d["candidates_analyzed"],
            "risk.overall": d["overall_risk"],
            "risk.validated_vulns": d["validated_count"],
            "risk.critical_high": d["critical_high_count"],
            "pipeline.steps": d["execution_steps"],
            "pipeline.tool_execution_rate": d["tool_execution_rate"],
            "pipeline.validation_rate": d["validation_rate"],
            "mitre.techniques": d["mitre_techniques"],
            "executive_summary": d.get("executive_summary",""),
            "validated_vulnerabilities": [
                {
                    "type": v.get("vuln_type",""), "severity": v.get("severity",""),
                    "owasp": v.get("owasp",""), "mitre_technique": v.get("mitre_technique",""),
                    "mitre_name": v.get("mitre_full_name",""),
                    "location": v.get("location",""),
                    "evidence": v.get("evidence", ""),
                    "remediation": v.get("remediation_text",""),
                }
                for v in d.get("validated_vulns",[])
            ],
            "potential_vulnerabilities": [
                {
                    "type": v.get("step_name", v.get("name", "Unknown Finding")),
                    "reason": v.get("evidence", v.get("reason", "Needs refinement context"))
                }
                for v in d.get("potential_vulns",[])
            ],
            "rejected_findings": [
                {
                    "target": v.get("name", v.get("step_name", "Unknown Finding")),
                    "rejection_reason": v.get("reason", v.get("evidence", "Insufficient evidence"))
                }
                for v in d.get("rejected_findings",[])
            ]
        }
        with open(path,"w",encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
