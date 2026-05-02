"""
Configuration — Phase 3
Pipeline: Recon(+ZAP) → VulnAnalyst → Planner(EKB) → Execution
Phase 3 note: ZAP is configured here but RUNS INSIDE ReconAgent as a tool.
"""
import os
from dotenv import load_dotenv
load_dotenv(override=True)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

MODELS = {
    "recon":    {"provider": "groq", "model": "llama-3.3-70b-versatile", "api_key": GROQ_API_KEY, "base_url": "https://api.groq.com/openai/v1", "max_tokens": 2048, "temperature": 0.1},
    "planner":  {"provider": "groq", "model": "llama-3.3-70b-versatile", "api_key": GROQ_API_KEY, "base_url": "https://api.groq.com/openai/v1", "max_tokens": 4096, "temperature": 0.2},
    "executor": {"provider": "groq", "model": "llama-3.3-70b-versatile", "api_key": GROQ_API_KEY, "base_url": "https://api.groq.com/openai/v1", "max_tokens": 2048, "temperature": 0.0},
    "analyst":  {"provider": "groq", "model": "llama-3.3-70b-versatile", "api_key": GROQ_API_KEY, "base_url": "https://api.groq.com/openai/v1", "max_tokens": 4096, "temperature": 0.1},
    "reporter": {"provider": "groq", "model": "llama-3.3-70b-versatile", "api_key": GROQ_API_KEY, "base_url": "https://api.groq.com/openai/v1", "max_tokens": 4096, "temperature": 0.2},
}

SAFETY = {
    "max_tool_calls": 30, "max_time_seconds": 240, "max_cost_usd": 0.30, "max_replan_attempts": 2,
    "require_human_approval_for": ["sql_injection_write", "file_upload_exploit", "reverse_shell", "privilege_escalation"],
    "allowed_targets_only": True,
}

TARGETS = {
    "dvwa":       {"name": "Damn Vulnerable Web App", "url": "http://localhost:9000", "docker_image": "vulnerables/web-dvwa", "difficulty": "simple"},
    "juice_shop": {"name": "OWASP Juice Shop",         "url": "http://localhost:3000", "docker_image": "bkimminich/juice-shop", "difficulty": "medium"},
}

OWASP_CATEGORIES = ["A01_Broken_Access_Control","A02_Cryptographic_Failures","A03_Injection","A04_Insecure_Design","A05_Security_Misconfiguration","A06_Vulnerable_Components","A07_Auth_Failures","A08_Software_Data_Integrity","A09_Logging_Failures","A10_SSRF","Unknown"]

PATHS = {"ekb_dir": "memory/ekb", "reports_dir": "reports", "logs_dir": "logs"}

EKB_SETTINGS = {
    "enabled": True, "ekb_dir": "memory/ekb",
    "min_similarity": 0.50, "top_k_retrieve": 3,
    "inject_threshold": 0.40, "store_failures": True,
    "embedder_model": "all-MiniLM-L6-v2",
}

# Phase 3: ZAP configuration
# ZAP runs INSIDE ReconAgent as a tool — not a separate pipeline stage
ZAP_SETTINGS = {
    "enabled":   True,
    "host":      "localhost",
    "port":      9002,
    "scan_type": "full",   # "passive" or "full"
    # Start ZAP: run start_zap.ps1
}

# ── Phase 4: Critique Agent + Sandbox Validator ──────────────
# Based on Co-RedTeam + MAPTA validation agent
PHASE4_SETTINGS = {
    "critique_enabled":   True,
    "sandbox_enabled":    True,
    # Only store EKB entries that passed critique
    "ekb_approved_only":  True,    # Only store critique-approved findings in EKB
    # Confidence boost for sandbox-verified findings
    "verified_confidence_bonus": 0.15,
}

# ── Phase 5: Curriculum Difficulty Scoring ────────────────────
# Based on CurriculumPT (Beijing Jiaotong 2025)
# D = 0.3·AC + 0.2·UI + 0.2·PR + 0.3·ES
PHASE5_SETTINGS = {
    "curriculum_enabled": True,
    # Tiers — matches CurriculumPT thresholds
    "simple_threshold":  0.30,   # D < 0.30
    "complex_threshold": 0.60,   # D >= 0.60
    # CurriculumPT ESR baselines for comparison
    "esr_baseline": {
        "simple":  0.953,  # 95.3%
        "medium":  0.750,  # 75%
        "complex": 0.600,  # 60%
    },
}

# ── Phase 6: Report Agent ─────────────────────────────────────
# Based on PENTEST-AI RA pattern + IEEE Web Collab ELK Stack
PHASE6_SETTINGS = {
    "report_enabled": True,
    "output_dir":     "reports",
    "generate_html":  True,
    "generate_elk":   True,
}

# ── Phase 7: Evaluation & Benchmarking ───────────────────────
# Runs pipeline multiple times across targets, measures ESR + FP rate
PHASE7_SETTINGS = {
    "benchmark_enabled":  True,
    "runs_per_target":    3,
    "pause_between_runs": 10,   # seconds — respect Groq rate limits
    # CurriculumPT ESR baselines for comparison
    "esr_baselines": {
        "simple":  0.953,
        "medium":  0.750,
        "complex": 0.600,
    },
    # MAPTA time baseline
    "time_baseline_s": 180,
}

# ── Phase 8: Intelligence Upgrades ───────────────────────────
# Based on: MultiVer, Co-RedTeam, MAPTA, CurriculumPT, MAVUL
PHASE8_SETTINGS = {
    # ── Parallel Sampling (MultiVer) ──────────────────────────
    # Run LLM N times at different temperatures for ambiguous vulns
    # Majority vote decides final verdict — reduces hallucination
    "parallel_sampling_enabled": True,
    "sampling_temperatures":     [0.3, 0.7, 1.0],
    "ambiguity_threshold":       0.60,   # vote_score < this → ambiguous → resample

    # ── Plan A / Plan B (Co-RedTeam + PentestMCP) ─────────────
    # If EKB match similarity >= threshold → reuse known plan (Plan B)
    # Else → generate new plan via LLM (Plan A)
    "plan_b_enabled":            True,
    "plan_b_similarity":         0.75,   # cosine similarity threshold

    # ── Early Stopping (MAPTA) ────────────────────────────────
    # Stop execution if cumulative LLM cost exceeds budget
    "early_stop_enabled":        True,
    "max_cost_usd":              0.30,   # MAPTA data: failures cost > $0.30

    # ── Dependency-Aware Execution ────────────────────────────
    # If a parent step fails, skip child steps that depend on it
    "dependency_check_enabled":  True,

    # ── Severity-Weighted ESR ─────────────────────────────────
    "severity_weights": {
        "critical": 1.0,
        "high":     1.0,
        "medium":   0.7,
        "low":      0.4,
    },
}
