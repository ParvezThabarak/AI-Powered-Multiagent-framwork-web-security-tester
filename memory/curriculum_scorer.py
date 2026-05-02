"""
Curriculum Difficulty Scorer — Phase 5 + Phase 8 ESR Fix

ARCHITECTURE ROLE:
  Runs alongside the pipeline. Scores each confirmed vulnerability
  by difficulty using CurriculumPT's formula:

    D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES

  Where:
    AC = Attack Complexity  (0.0 low, 0.5 medium, 1.0 high)
    UI = User Interaction   (0.0 none, 1.0 required)
    PR = Privileges Required(0.0 none, 0.5 low, 1.0 high)
    ES = Expected Severity  (0.0 info, 0.33 low, 0.66 med, 1.0 high/critical)

  Score ranges:
    Simple:  D < 0.30  — basic SQLi, reflected XSS, missing headers
    Medium:  0.30 ≤ D < 0.60  — LFI, stored XSS, auth bypass
    Complex: D ≥ 0.60  — RCE, SSRF, chained attacks

  The Curriculum Scheduler uses these scores to:
    1. Prioritise which vulns to exploit first (easy → hard)
    2. Track ESR (Exploit Success Rate) per difficulty tier
    3. Decide when to advance to harder targets in the EKB

Based on:
  CurriculumPT (Beijing Jiaotong 2025):
    D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES
    ESR: 95.3% simple, 75% medium, 60% complex
  MAPTA (UCL 2025): cost and time per difficulty tier
"""

from datetime import datetime


# ── Difficulty formula weights (CurriculumPT) ─────────────────
WEIGHTS = {"AC": 0.3, "UI": 0.2, "PR": 0.2, "ES": 0.3}

# ── Per-vuln-type default component scores ─────────────────────
# Based on CVSS v3 component values for OWASP vuln categories
VULN_PROFILES = {
    "SQLi": {
        "AC": 0.0,   # low — just craft a payload
        "UI": 0.0,   # none
        "PR": 0.0,   # none needed
        "ES": 1.0,   # high impact — DB access
        "owasp": "A03_Injection",
        "mitre": "T1190",
    },
    "XSS": {
        "AC": 0.0,
        "UI": 1.0,   # requires victim to click
        "PR": 0.0,
        "ES": 0.66,  # medium — session hijack
        "owasp": "A03_Injection",
        "mitre": "T1189",
    },
    "LFI": {
        "AC": 0.5,   # medium — needs traversal bypass
        "UI": 0.0,
        "PR": 0.0,
        "ES": 0.66,
        "owasp": "A05_Security_Misconfiguration",
        "mitre": "T1083",
    },
    "RFI": {
        "AC": 0.5,
        "UI": 0.0,
        "PR": 0.0,
        "ES": 1.0,   # high — remote code inclusion
        "owasp": "A03_Injection",
        "mitre": "T1190",
    },
    "RCE": {
        "AC": 1.0,   # high — complex exploit chain
        "UI": 0.0,
        "PR": 0.5,
        "ES": 1.0,
        "owasp": "A03_Injection",
        "mitre": "T1190",
    },
    "Auth_Bypass": {
        "AC": 0.5,
        "UI": 0.0,
        "PR": 0.0,
        "ES": 1.0,
        "owasp": "A07_Auth_Failures",
        "mitre": "T1078",
    },
    "SSRF": {
        "AC": 1.0,
        "UI": 0.0,
        "PR": 0.5,
        "ES": 1.0,
        "owasp": "A10_SSRF",
        "mitre": "T1090",
    },
    "CSRF": {
        "AC": 0.5,
        "UI": 1.0,
        "PR": 0.0,
        "ES": 0.66,
        "owasp": "A01_Broken_Access_Control",
        "mitre": "T1189",
    },
    "Misconfiguration": {
        "AC": 0.0,
        "UI": 0.0,
        "PR": 0.0,
        "ES": 0.33,  # low — info disclosure mostly
        "owasp": "A05_Security_Misconfiguration",
        "mitre": "T1592",
    },
    "A06_Security_Misconfiguration": {
        "AC": 0.0, "UI": 0.0, "PR": 0.0, "ES": 0.33,
        "owasp": "A05_Security_Misconfiguration", "mitre": "T1592",
    },
    "Unknown": {
        "AC": 0.5, "UI": 0.5, "PR": 0.5, "ES": 0.5,
        "owasp": "Unknown", "mitre": "T1190",
    },
}

TIER_LABELS = {
    "simple":  "Simple  (D < 0.30)",
    "medium":  "Medium  (0.30 ≤ D < 0.60)",
    "complex": "Complex (D ≥ 0.60)",
}


class CurriculumScorer:
    """
    Scores confirmed vulnerabilities by difficulty.

    Pipeline position: runs after VulnAnalyst (Step 2),
    before PlannerAgent (Step 3). Enriches vuln_summary
    with difficulty scores so Planner attacks easiest first.

    Also tracks ESR per difficulty tier across runs.
    """

    def __init__(self):
        self.session_results = []  # (vuln_type, difficulty, success)

    def score_analysis_report(self, analysis_report: dict) -> dict:
        """
        Score every confirmed vulnerability in the analysis report.
        Adds 'difficulty', 'difficulty_score', and 'curriculum_tier'
        to each entry in vuln_summary.
        Sorts vuln_summary: simple → medium → complex.

        Returns enriched analysis_report (modifies in place + returns).
        """
        vulns = analysis_report.get("vuln_summary", [])
        if not vulns:
            return analysis_report

        print(f"\n[CurriculumScorer] 📊 Scoring {len(vulns)} confirmed vulnerabilities...")
        print(f"[CurriculumScorer] Formula: D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES")
        print("-" * 50)

        scored = []
        for v in vulns:
            vuln_type = v.get("vuln_type", "Unknown")
            severity  = v.get("severity", "informational")
            scored_v  = self._score_vuln(v, vuln_type, severity)
            scored.append(scored_v)

            tier  = scored_v["curriculum_tier"]
            score = scored_v["difficulty_score"]
            print(f"[CurriculumScorer]   {vuln_type:<25} "
                  f"D={score:.3f}  → {tier.upper()}")

        # Sort simple → medium → complex (easiest first)
        tier_order = {"simple": 0, "medium": 1, "complex": 2}
        scored.sort(key=lambda x: tier_order.get(x["curriculum_tier"], 1))

        analysis_report["vuln_summary"] = scored

        # Build curriculum summary
        summary = self._build_summary(scored)
        analysis_report["curriculum_summary"] = summary

        print(f"\n[CurriculumScorer] ✅ Scoring complete")
        print(f"[CurriculumScorer]   Simple:  {summary['simple_count']}")
        print(f"[CurriculumScorer]   Medium:  {summary['medium_count']}")
        print(f"[CurriculumScorer]   Complex: {summary['complex_count']}")
        print(f"[CurriculumScorer]   Recommended start: {summary['recommended_start']}")

        return analysis_report

    def _score_vuln(self, vuln: dict, vuln_type: str, severity: str) -> dict:
        """Score a single vulnerability using CurriculumPT formula."""
        # Look up profile — try exact match, then prefix match
        profile = VULN_PROFILES.get(vuln_type)
        if not profile:
            for key in VULN_PROFILES:
                if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                    profile = VULN_PROFILES[key]
                    break
        if not profile:
            profile = VULN_PROFILES["Unknown"]

        # Override ES from actual severity reported by VulnAnalyst
        severity_map = {
            "critical":      1.0,
            "high":          1.0,
            "medium":        0.66,
            "low":           0.33,
            "informational": 0.0,
        }
        es = severity_map.get(severity.lower(), profile["ES"])

        ac = profile["AC"]
        ui = profile["UI"]
        pr = profile["PR"]

        # D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES
        score = (
            WEIGHTS["AC"] * ac +
            WEIGHTS["UI"] * ui +
            WEIGHTS["PR"] * pr +
            WEIGHTS["ES"] * es
        )
        score = round(score, 4)

        # Tier classification
        if score < 0.30:
            tier = "simple"
        elif score < 0.60:
            tier = "medium"
        else:
            tier = "complex"

        enriched = dict(vuln)
        enriched.update({
            "difficulty_score":    score,
            "curriculum_tier":     tier,
            "difficulty":          tier,   # also update the difficulty field used by Planner
            "score_components":    {"AC": ac, "UI": ui, "PR": pr, "ES": es},
            "tier_label":          TIER_LABELS[tier],
        })
        return enriched

    def _build_summary(self, scored_vulns: list) -> dict:
        """Build curriculum summary stats."""
        tiers = [v["curriculum_tier"] for v in scored_vulns]
        simple_count  = tiers.count("simple")
        medium_count  = tiers.count("medium")
        complex_count = tiers.count("complex")

        # Recommended start = easiest confirmed vuln
        if simple_count > 0:
            start = "simple"
        elif medium_count > 0:
            start = "medium"
        else:
            start = "complex"

        avg_score = (sum(v["difficulty_score"] for v in scored_vulns)
                     / max(len(scored_vulns), 1))

        return {
            "total_scored":       len(scored_vulns),
            "simple_count":       simple_count,
            "medium_count":       medium_count,
            "complex_count":      complex_count,
            "average_score":      round(avg_score, 3),
            "recommended_start":  start,
            "tier_label":         TIER_LABELS[start],
            "formula":            "D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES",
            "source":             "CurriculumPT (Beijing Jiaotong 2025)",
        }

    def record_result(self, vuln_type: str, tier: str, success: bool,
                       severity: str = "medium"):
        """Record an execution result for ESR tracking.
        Phase 8: now tracks severity for weighted ESR calculation."""
        self.session_results.append({
            "vuln_type": vuln_type,
            "tier":      tier,
            "success":   success,
            "severity":  severity.lower() if severity else "medium",
            "timestamp": datetime.now().isoformat(),
        })

    def get_esr(self) -> dict:
        """
        Calculate Exploit Success Rate per difficulty tier.
        Phase 8 FIX: ESR = verified / confirmed (not approved / confirmed).
        Also calculates severity-weighted ESR.
        CurriculumPT baseline: 95.3% simple, 75% medium, 60% complex.
        """
        if not self.session_results:
            return {}

        # Severity weights for weighted ESR (Phase 8)
        _sev_weights = {
            "critical": 1.0, "high": 1.0, "medium": 0.7, "low": 0.4,
            "informational": 0.1,
        }

        esr = {}
        for tier in ["simple", "medium", "complex"]:
            tier_results = [r for r in self.session_results if r["tier"] == tier]
            if tier_results:
                successes = sum(1 for r in tier_results if r["success"])
                # Standard ESR
                esr[tier] = {
                    "attempts":  len(tier_results),
                    "successes": successes,
                    "esr":       round(successes / len(tier_results), 3),
                    "esr_pct":   f"{successes/len(tier_results)*100:.1f}%",
                }
                # Severity-weighted ESR (Phase 8)
                weighted_num = sum(
                    _sev_weights.get(r.get("severity", "medium"), 0.5)
                    for r in tier_results if r["success"]
                )
                weighted_den = sum(
                    _sev_weights.get(r.get("severity", "medium"), 0.5)
                    for r in tier_results
                )
                if weighted_den > 0:
                    esr[tier]["weighted_esr"] = round(weighted_num / weighted_den, 3)
                    esr[tier]["weighted_esr_pct"] = f"{weighted_num/weighted_den*100:.1f}%"
        return esr
