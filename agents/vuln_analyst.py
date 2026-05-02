"""
Vulnerability Analyst Agent — Phase 1 (Corrected Architecture)

ARCHITECTURE ROLE:
  Step 2 of 5 in the pipeline.
  Receives the full recon report (which already includes ZAP alerts,
  discovered URLs, and injectable candidates from ReconAgent).
  Analyses and CONFIRMS which vulnerabilities are real.
  Output feeds directly into PlannerAgent (Step 3).

  Old (wrong): VulnAnalyst ran AFTER execution, analysed execution findings
  New (correct): VulnAnalyst runs AFTER recon, BEFORE planning
                 Planner only plans exploitation of CONFIRMED vulns

Based on:
- MultiVer (Harvard 2026): 4-agent ensemble voting
  Security(0.45) + Correctness(0.35) + Performance(0.15) + CVE(0.05)
  82.7% recall, 61.4% F1 on PyVul dataset
- MAVUL (UT Dallas 2025): Analyst + Architect + Judge pattern
- Co-RedTeam (Google 2026): Stage I is Analysis BEFORE planning
"""

import json
import re
from agents.llm_client import LLMClient
from config.config import PHASE8_SETTINGS


SECURITY_ANALYST_PROMPT = """You are a Security Analyst agent specialising in web application vulnerabilities.
Analyse the provided finding and determine:
1. Is this a real vulnerability? (true/false)
2. Vulnerability type (SQLi/XSS/LFI/RCE/Auth_Bypass/SSRF/CSRF/Misconfiguration/Other)
3. Severity (critical/high/medium/low/informational)
4. OWASP Top 10 category (e.g. A03_Injection)
5. Confidence score (0.0-1.0)

Respond ONLY with valid JSON:
{
  "is_vulnerable": true/false,
  "vuln_type": "...",
  "severity": "critical/high/medium/low/informational",
  "owasp": "A0X_...",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}"""

CORRECTNESS_CHECK_PROMPT = """You are a Correctness Verification agent. Your job is to identify false positives.
A scanner reported a potential vulnerability. Critically evaluate:
1. Is this a genuine vulnerability or a false positive?
2. Does the evidence actually support the claimed vulnerability type?
3. Could this be a scanner artifact?

Be sceptical. Many scanner findings are false positives.

Respond ONLY with valid JSON:
{
  "is_real_finding": true/false,
  "false_positive_risk": "high/medium/low",
  "evidence_quality": "strong/moderate/weak/none",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}"""

PERFORMANCE_EVAL_PROMPT = """You are an Impact Assessment agent evaluating vulnerability impact.
Assess:
1. Exploitability — how easy is this to exploit? (trivial/easy/moderate/difficult/theoretical)
2. Impact type — what damage can an attacker cause?
3. Attack complexity
4. Priority

Respond ONLY with valid JSON:
{
  "exploitability": "trivial/easy/moderate/difficult/theoretical",
  "impact_type": ["data_breach"],
  "attack_complexity": "low/medium/high",
  "priority": "immediate/high/medium/low/informational",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}"""

CVE_MAPPER_PROMPT = """You are a CVE and MITRE ATT&CK mapping agent.
Map the vulnerability to:
1. MITRE ATT&CK technique ID (e.g. T1190)
2. CWE ID (e.g. CWE-89 for SQLi)
3. Relevant CVE IDs if server version is known
4. Recommended remediation

Respond ONLY with valid JSON:
{
  "cve_ids": [],
  "mitre_technique": "TXXXX",
  "mitre_name": "technique name",
  "cwe_id": "CWE-XX",
  "remediation": "brief fix",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}"""

ENSEMBLE_WEIGHTS = {
    "security":    0.45,
    "correctness": 0.35,
    "performance": 0.15,
    "cve_mapper":  0.05,
}


class VulnAnalystAgent:
    """
    Vulnerability Analyst — Step 2 of pipeline.

    Corrected position: runs AFTER ReconAgent, BEFORE PlannerAgent.
    Receives the full recon report (includes ZAP alerts + injectable candidates).
    Confirms which findings are real vulnerabilities.
    Planner only plans exploitation of confirmed vulns.

    Uses MultiVer 4-agent ensemble voting for high-confidence results.
    """

    def __init__(self):
        self.llm_security    = LLMClient("analyst")
        self.llm_correctness = LLMClient("analyst")
        self.llm_performance = LLMClient("analyst")
        self.llm_cve         = LLMClient("analyst")

    def analyse(self, recon_report: dict) -> dict:
        """
        Analyse all findings from the recon report.

        recon_report: full output from ReconAgent.run()
        Returns: structured analysis with confirmed vulns for PlannerAgent
        """
        target_url  = recon_report.get("target_url", "")
        web_server  = recon_report.get("web_server", "Unknown")
        zap_alerts  = recon_report.get("zap_alerts", [])
        pot_vulns   = recon_report.get("potential_vulns", [])
        injectables = recon_report.get("injectable_candidates", [])

        print(f"\n[VulnAnalyst] 🔬 Analysing findings from recon...")
        print(f"[VulnAnalyst] Target: {target_url} ({web_server})")
        print(f"[VulnAnalyst] ZAP alerts: {len(zap_alerts)}")
        print(f"[VulnAnalyst] Potential vulns: {len(pot_vulns)}")
        print(f"[VulnAnalyst] Injectable candidates: {len(injectables)}")
        print(f"[VulnAnalyst] Method: MultiVer 4-agent ensemble")
        print("-" * 50)

        # Build finding list from all recon sources
        findings = self._collect_findings(zap_alerts, pot_vulns, injectables, target_url)

        # Cache: skip LLM call if same alert name+param seen this run
        _analysis_cache = {}
        analysed = []
        for i, finding in enumerate(findings, 1):
            if not finding.get("description"):
                continue
            print(f"\n[VulnAnalyst] 🧩 Finding {i}/{len(findings)}: {finding['description'][:70]}...")

            # Cache key = first 60 chars of description + param (normalised)
            desc_key  = finding["description"][:60].strip().lower()
            param_key = str(finding.get("param","")).strip().lower()
            cache_key = (desc_key, param_key)

            if cache_key in _analysis_cache:
                cached = dict(_analysis_cache[cache_key])
                cached["location"] = finding.get("location", cached.get("location",""))
                analysed.append(cached)
                print(f"[VulnAnalyst]   ♻️  Cache hit — reusing analysis (saved 4 LLM calls)")
                continue

            result = self._ensemble_analyse(
                finding    = finding["description"],
                web_server = web_server,
                target_url = target_url,
                location   = finding.get("location", target_url),
                param      = finding.get("param", ""),
            )
            _analysis_cache[cache_key] = result
            analysed.append(result)

        # Deduplicate by vuln type
        analysed = self._deduplicate(analysed)

        report = self._build_report(analysed, target_url, web_server, recon_report)

        print(f"\n[VulnAnalyst] ✅ Analysis complete")
        print(f"[VulnAnalyst] Confirmed: {report['confirmed_count']}")
        print(f"[VulnAnalyst] False positives filtered: {report['false_positive_count']}")
        print(f"[VulnAnalyst] Critical/High: {report['critical_high_count']}")

        return report

    # Keywords that indicate a real vuln regardless of ZAP risk rating
    VULN_KEYWORDS = [
        "sql", "injection", "xss", "cross-site", "traversal", "path",
        "lfi", "rfi", "csrf", "ssrf", "xxe", "rce", "command",
        "auth", "bypass", "disclosure", "sensitive", "password",
        "token", "session", "cookie", "header", "redirect", "open",
        "upload", "deserialization", "overflow",
    ]

    # ZAP risk priority for sorting
    _RISK_PRIORITY = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}

    def _collect_findings(self, zap_alerts, pot_vulns, injectables, target_url) -> list:
        """
        Two-stage filter:

        Stage 1 (fast, no LLM): keyword + risk pre-filter on all ZAP alerts.
          - Accept High/Medium always
          - Accept Low if alert name contains a known vuln keyword
          - REJECT Informational entirely from ensemble (stored as context_signals)
          - Deduplicate by alert name (keep highest-risk instance)
          - Cap at 15 findings to stay within Groq rate limits

        Stage 2 (LLM ensemble): runs only on the shortlisted findings.
        """
        findings = []
        seen_names = {}
        self._context_signals = []  # Informational alerts stored here for auth/session awareness

        # Stage 1a: Pre-filter ZAP alerts
        for a in zap_alerts:
            name       = a.get("name", "Unknown")
            risk       = a.get("risk", "Informational")
            risk_pri   = self._RISK_PRIORITY.get(risk, 0)
            name_lower = name.lower()

            # Informational alerts → store as context signals, never send to ensemble
            if risk == "Informational":
                if any(kw in name_lower for kw in self.VULN_KEYWORDS):
                    self._context_signals.append({
                        "name": name, "url": a.get("url", ""),
                        "param": a.get("param", ""), "risk": risk,
                    })
                continue

            is_relevant = (
                risk in ["High", "Medium"] or
                (risk == "Low" and
                 any(kw in name_lower for kw in self.VULN_KEYWORDS))
            )
            if not is_relevant:
                continue

            # Deduplicate by name, keep highest-risk instance
            if name in seen_names:
                if risk_pri <= self._RISK_PRIORITY.get(seen_names[name]["risk"], 0):
                    continue

            seen_names[name] = {
                "risk":        risk,
                "description": (f"ZAP [{risk}] {name} "
                                f"at {a.get('url', target_url)} "
                                f"param='{a.get('param','')}' "
                                f"{a.get('solution','')[:80]}"),
                "location":    a.get("url", target_url),
                "param":       a.get("param", ""),
                "source":      "zap",
            }

        # Dynamic shortlist cap — scale with alert volume
        # Juice Shop returns 200+ alerts; DVWA/WebGoat ~100-140
        # Keep more for large targets to improve coverage without rate-limit spam
        _cap = 15 if len(zap_alerts) > 100 else 10
        zap_findings = sorted(
            seen_names.values(),
            key=lambda x: self._RISK_PRIORITY.get(x["risk"], 0),
            reverse=True,
        )[:_cap]

        findings.extend(zap_findings)

        # Show ZAP risk distribution so we can see what real ZAP returned
        if zap_alerts:
            risk_dist = {}
            for a in zap_alerts:
                r = a.get("risk", "?")
                risk_dist[r] = risk_dist.get(r, 0) + 1
            print(f"[VulnAnalyst] ZAP risk distribution: {risk_dist}")
        print(f"[VulnAnalyst] Pre-filter: {len(zap_alerts)} ZAP alerts "
              f"-> {len(zap_findings)} shortlisted for ensemble"
              f" ({len(self._context_signals)} informational stored as context)")

        # Stage 1b: Injectable candidates from URL discovery
        # Always include — even "Unknown" type, real params matter
        for c in injectables[:8]:   # keep top-8 — more = more LLM calls
            vuln_types = c.get("vuln_types", [])
            label = ", ".join(vuln_types) if vuln_types and vuln_types != ["Unknown"] \
                    else "possible injection point"
            findings.append({
                "description": (f"Parameterised URL: param '{c.get('param','?')}' "
                                f"at {c.get('url','')} — {label}"),
                "location":    c.get("url", target_url),
                "param":       c.get("param", ""),
                "source":      "url_discovery",
                "risk":        "Low",
            })

        # Stage 1c: Directory enum findings
        for v in pot_vulns:
            if v.get("source") != "zap":
                findings.append({
                    "description": (f"{v.get('type','Unknown')} "
                                    f"at {v.get('location', target_url)}"),
                    "location":    v.get("location", target_url),
                    "param":       "",
                    "source":      "dir_enum",
                    "risk":        v.get("severity", "low").capitalize(),
                })

        return findings
    def _ensemble_analyse(self, finding: str, web_server: str,
                           target_url: str, location: str, param: str) -> dict:
        """Run 4 sub-agents and combine via weighted vote.
        Phase 8: if vote_score is ambiguous, re-sample with parallel temperatures."""
        context = (f"TARGET: {target_url}\nWEB SERVER: {web_server}\n"
                   f"LOCATION: {location}\nPARAMETER: {param}\nFINDING: {finding}")

        s = self._run_agent(self.llm_security,    SECURITY_ANALYST_PROMPT,  context, "security")
        c = self._run_agent(self.llm_correctness, CORRECTNESS_CHECK_PROMPT, context, "correctness")
        p = self._run_agent(self.llm_performance, PERFORMANCE_EVAL_PROMPT,  context, "performance")
        v = self._run_agent(self.llm_cve,         CVE_MAPPER_PROMPT,         context, "cve_mapper")

        verdict = self._weighted_vote(s, c, p, v)

        # Phase 8 — Parallel Sampling for ambiguous findings (MultiVer)
        if (PHASE8_SETTINGS.get("parallel_sampling_enabled")
                and verdict.get("vote_score", 1.0) < PHASE8_SETTINGS.get("ambiguity_threshold", 0.60)):
            verdict = self._parallel_sample(context, verdict, c, p, v)

        return {
            "finding":          finding[:200],
            "location":         location,
            "param":            param,
            "verdict":          verdict,
            "security_analysis":  s,
            "correctness_check":  c,
            "performance_eval":   p,
            "cve_mapping":        v,
        }

    def _parallel_sample(self, context: str, original_verdict: dict,
                          c: dict, p: dict, v: dict) -> dict:
        """Phase 8: Re-run Security Agent at multiple temperatures and majority-vote.
        Based on MultiVer (Harvard 2026) self-consistency sampling.
        Only invoked for ambiguous findings (vote_score < threshold)."""
        temps = PHASE8_SETTINGS.get("sampling_temperatures", [0.3, 0.7, 1.0])
        print(f"[VulnAnalyst]   🔄 Ambiguous (score={original_verdict['vote_score']:.2f}) — "
              f"parallel sampling at temps {temps}")

        votes_true = 0
        votes_total = 0
        best_s = None

        for temp in temps:
            # Temporarily override temperature for this call
            original_temp = self.llm_security.config.get("temperature", 0.1)
            self.llm_security.config["temperature"] = temp
            try:
                s_sample = self._run_agent(
                    self.llm_security, SECURITY_ANALYST_PROMPT, context, "security")
                if s_sample.get("is_vulnerable"):
                    votes_true += 1
                    if best_s is None:
                        best_s = s_sample
                votes_total += 1
            finally:
                self.llm_security.config["temperature"] = original_temp

        # Majority vote: 2/3 must agree it's a vulnerability
        majority_confirms = votes_true > votes_total / 2
        print(f"[VulnAnalyst]   📊 Parallel vote: {votes_true}/{votes_total} confirm "
              f"→ {'CONFIRMED' if majority_confirms else 'REJECTED'}")

        if majority_confirms and best_s:
            # Re-run weighted vote with the best security sample
            return self._weighted_vote(best_s, c, p, v)
        else:
            # Majority says false positive — override original
            rejected = dict(original_verdict)
            rejected["is_confirmed"] = False
            rejected["is_false_positive"] = True
            rejected["parallel_sampling"] = f"{votes_true}/{votes_total} confirmed"
            return rejected

    def _run_agent(self, llm, system_prompt, context, role) -> dict:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": f"Analyse:\n{context}"},
        ]
        try:
            response = llm.chat(messages)
            parsed   = self._extract_json(str(response))
            if parsed:
                parsed["agent_role"] = role
                return parsed
        except Exception as e:
            print(f"[VulnAnalyst]   ⚠️  {role} agent error: {e}")
        return {"agent_role": role, "confidence": 0.0, "error": "failed"}

    def _weighted_vote(self, s, c, p, v) -> dict:
        w  = ENSEMBLE_WEIGHTS
        is_vuln_score = (
            (1.0 if s.get("is_vulnerable")     else 0.0) * w["security"] +
            (1.0 if c.get("is_real_finding")   else 0.0) * w["correctness"] +
            (1.0 if p.get("exploitability", "theoretical") != "theoretical" else 0.0) * w["performance"] +
            w["cve_mapper"] * (1.0 if v.get("cve_ids") else 0.5)
        )
        is_confirmed = is_vuln_score >= 0.5
        severity     = s.get("severity", "informational") if is_confirmed else "informational"
        confidence   = sum([
            s.get("confidence", 0.0) * w["security"],
            c.get("confidence", 0.0) * w["correctness"],
            p.get("confidence", 0.0) * w["performance"],
            v.get("confidence", 0.0) * w["cve_mapper"],
        ])
        return {
            "is_confirmed":      is_confirmed,
            "is_false_positive": not is_confirmed,
            "confidence":        round(confidence, 3),
            "vote_score":        round(is_vuln_score, 3),
            "severity":          severity,
            "vuln_type":         s.get("vuln_type", "Unknown"),
            "owasp":             s.get("owasp", "Unknown"),
            "exploitability":    p.get("exploitability", "unknown"),
            "impact_types":      p.get("impact_type", []),
            "priority":          p.get("priority", "low"),
            "cve_ids":           v.get("cve_ids", []),
            "mitre_technique":   v.get("mitre_technique", ""),
            "mitre_name":        v.get("mitre_name", ""),
            "cwe_id":            v.get("cwe_id", ""),
            "remediation":       v.get("remediation", ""),
        }

    def _deduplicate(self, analyses: list) -> list:
        seen, deduped = set(), []
        for a in analyses:
            key = a.get("verdict", {}).get("vuln_type", "Unknown")
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        return deduped

    def _build_report(self, analyses: list, target_url: str,
                       web_server: str, recon_report: dict) -> dict:
        confirmed = [a for a in analyses if a.get("verdict", {}).get("is_confirmed")]
        fps       = [a for a in analyses if a.get("verdict", {}).get("is_false_positive")]
        crit_high = [a for a in confirmed
                     if a.get("verdict", {}).get("severity") in ["critical", "high"]]

        vuln_summary = []
        for a in confirmed:
            v = a.get("verdict", {})
            vuln_summary.append({
                "vuln_type":       v.get("vuln_type"),
                "severity":        v.get("severity"),
                "confidence":      v.get("confidence"),
                "owasp":           v.get("owasp"),
                "exploitability":  v.get("exploitability"),
                "impact_types":    v.get("impact_types", []),
                "priority":        v.get("priority"),
                "cve_ids":         v.get("cve_ids", []),
                "mitre_technique": v.get("mitre_technique"),
                "mitre_name":      v.get("mitre_name"),
                "cwe_id":          v.get("cwe_id"),
                "remediation":     v.get("remediation"),
                "location":        a.get("location", target_url),
                "param":           a.get("param", ""),
                "finding":         a.get("finding", "")[:200],
            })

        return {
            "target_url":           target_url,
            "web_server":           web_server,
            "confirmed_count":      len(confirmed),
            "false_positive_count": len(fps),
            "critical_high_count":  len(crit_high),
            "vuln_summary":         vuln_summary,
            "all_analyses":         analyses,
            "ensemble_method":      "MultiVer 4-agent weighted vote",
            "weights":              ENSEMBLE_WEIGHTS,
            # Pass recon data through so Planner can use injectable candidates
            "recon_summary": {
                "injectable_candidates": recon_report.get("injectable_candidates", []),
                "found_paths":           recon_report.get("found_paths", []),
                "web_server":            web_server,
                "zap_risk_counts":       recon_report.get("zap_risk_counts", {}),
            },
        }

    def _extract_json(self, text: str) -> dict | None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        return None
