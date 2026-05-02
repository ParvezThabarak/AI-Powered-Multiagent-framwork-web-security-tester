"""
EKB Builder — Phase 2
Automatically extracts structured experiences from execution reports
and stores them in the EKB after every pipeline run.

Based on:
- CurriculumPT: Report Agent "aggregates complete execution traces,
  updates EKB with distilled experience entries in structured formats"
- Co-RedTeam: Technical Action memory layer stores exact tool sequences
- PentestMCP: RAG knowledge base updated after each exploitation attempt
"""

from memory.ekb import ExperienceKnowledgeBase, make_ekb_entry


class EKBBuilder:
    """
    Converts pipeline execution reports into EKB entries.
    Called automatically at the end of each pipeline run.
    """

    def __init__(self, ekb: ExperienceKnowledgeBase):
        self.ekb = ekb

    def extract_and_store(self, pipeline_report: dict) -> list[str]:
        """
        Extract experiences from a full pipeline report and store them.

        pipeline_report: the final_report dict from main.py run_pipeline()

        Returns: list of stored entry IDs
        """
        stored_ids = []

        recon     = pipeline_report.get("recon", {})
        execution = pipeline_report.get("execution", {})
        plan      = pipeline_report.get("plan", {})
        crawl     = pipeline_report.get("crawl", {})

        target_url  = pipeline_report.get("target_url", "")
        web_server  = recon.get("web_server", "Unknown")
        difficulty  = plan.get("difficulty", "simple")
        owasp_cats  = plan.get("owasp_categories", ["Unknown"])
        injectable  = crawl.get("injectable_targets", [])

        step_results = execution.get("step_results", [])

        # Build one EKB entry per successful step
        # (CurriculumPT stores both successes and failures)
        for step_result in step_results:
            status   = step_result.get("status", "failed")
            success  = status == "success"
            critique_verdict = step_result.get("critique_verdict", "UNKNOWN")
            sandbox_verified = bool(step_result.get("sandbox_verified", False))
            findings = step_result.get("findings", [])
            tool_outputs = step_result.get("tool_outputs", [])

            # Strict storage: only sandbox-verified and critique-approved findings enter EKB.
            if not (success and critique_verdict == "APPROVED" and sandbox_verified):
                continue

            # Determine vuln type from step name + findings
            vuln_type = self._infer_vuln_type(
                step_result.get("name", ""),
                findings,
                plan
            )

            # Build steps list from tool outputs
            steps = [
                {
                    "tool":   t.get("tool", ""),
                    "args":   t.get("args", {}),
                    "output": str(t.get("output", {}).get("stdout", ""))[:300],
                }
                for t in tool_outputs
            ]

            # Get relevant injectable params for this step
            params = self._get_relevant_params(step_result, injectable)

            entry = make_ekb_entry(
                target_url       = target_url,
                vuln_type        = vuln_type,
                owasp            = owasp_cats[0] if owasp_cats else "Unknown",
                difficulty       = difficulty,
                success          = success,
                steps            = steps,
                findings         = findings,
                web_server       = web_server,
                injectable_params= params,
                notes            = f"Step: {step_result.get('name', '')} | Attempts: {step_result.get('attempts', 1)}",
            )

            entry_id = self.ekb.store(entry)
            stored_ids.append(entry_id)

        # Keep EKB strict and exploit-focused: no pipeline summary storage.

        print(f"\n[EKBBuilder] 💾 Stored {len(stored_ids)} experiences in EKB")
        return stored_ids

    def _infer_vuln_type(self, step_name: str, findings: list, plan: dict) -> str:
        """Infer vulnerability type from step name and findings."""
        name     = step_name.lower()
        findings_str = " ".join([str(f).lower() for f in findings])

        if any(kw in name or kw in findings_str for kw in ["sql", "injection", "sqli", "sqlmap"]):
            return "SQLi"
        if any(kw in name or kw in findings_str for kw in ["xss", "cross-site", "script"]):
            return "XSS"
        if any(kw in name or kw in findings_str for kw in ["lfi", "file inclusion", "path traversal", "directory"]):
            return "LFI"
        if any(kw in name or kw in findings_str for kw in ["csrf", "cross-site request"]):
            return "CSRF"
        if any(kw in name or kw in findings_str for kw in ["login", "auth", "credential", "bypass", "brute"]):
            return "Auth_Bypass"
        if any(kw in name or kw in findings_str for kw in ["upload", "file upload"]):
            return "File_Upload"
        if any(kw in name or kw in findings_str for kw in ["port", "service", "scan", "nmap"]):
            return "Recon"
        if any(kw in name or kw in findings_str for kw in ["ssrf", "server-side request"]):
            return "SSRF"
        if any(kw in name or kw in findings_str for kw in ["rce", "command", "exec", "shell"]):
            return "RCE"

        # Fall back to plan's first OWASP category
        owasp = plan.get("owasp_categories", ["Unknown"])
        return owasp[0] if owasp else "Unknown"

    def _get_relevant_params(self, step_result: dict, injectable: list) -> list:
        """Extract relevant injectable params for this step."""
        findings_str = " ".join([str(f).lower() for f in step_result.get("findings", [])])
        relevant = []
        for target in injectable:
            url = target.get("url", "")
            if any(p in findings_str for p in target.get("params", [])):
                relevant.append(url)
        return relevant[:3]
