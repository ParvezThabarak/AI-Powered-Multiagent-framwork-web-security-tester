"""
Experience Knowledge Base (EKB) — Phase 2
The memory system of the AI Security Tester.

Based on:
- CurriculumPT: EKB stores successful exploits as structured JSON,
  retrieved via semantic similarity to guide future attacks.
  "EHR improves from 67.9% → 81.7% as task complexity increases"
- PentestMCP: RAG with MongoDB + all-MiniLM-L6-v2 embeddings,
  cosine similarity ≥ 0.90 for Plan B matching
- MultiVer: FAISS k=5 retrieval with 1199 examples
- Co-RedTeam: 3-layer memory (Vulnerability Pattern + Strategy + Technical Action)

Architecture:
  EKB has 3 storage layers (matching Co-RedTeam):
  Layer 1 — Vulnerability Patterns   (what vulns look like)
  Layer 2 — Exploit Strategies       (how to attack them)
  Layer 3 — Technical Actions        (exact commands that worked)

Storage:
  - JSON files on disk (one per exploit experience)
  - FAISS vector index for semantic search
  - Falls back to keyword search if FAISS unavailable
"""

import json
import os
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────
# EKB ENTRY SCHEMA
# Based on CurriculumPT's structured exploitation case format
# ─────────────────────────────────────────────────────────────

def make_ekb_entry(
    target_url:    str,
    vuln_type:     str,        # e.g. "SQLi", "XSS", "LFI", "Auth_Bypass"
    owasp:         str,        # e.g. "A03_Injection"
    difficulty:    str,        # "simple" / "medium" / "complex"
    success:       bool,
    steps:         list,       # list of {tool, args, output} dicts
    findings:      list,       # what was discovered
    web_server:    str = "",
    cve_id:        str = "",
    notes:         str = "",
    injectable_params: list = None,
) -> dict:
    """
    Create a structured EKB entry from an execution result.
    This is what gets stored and retrieved for future attacks.
    """
    return {
        "id":               _generate_id(target_url, vuln_type),
        "timestamp":        datetime.now().isoformat(),
        "target_url":       target_url,
        "web_server":       web_server,
        "cve_id":           cve_id,
        "vuln_type":        vuln_type,
        "owasp_category":   owasp,
        "difficulty":       difficulty,
        "success":          success,
        "injectable_params": injectable_params or [],
        "steps":            steps,
        "findings":         findings,
        "notes":            notes,
        # CurriculumPT: these fields used for retrieval scoring
        "retrieval_text":   _build_retrieval_text(vuln_type, web_server, owasp, steps, findings),
    }


def _generate_id(target: str, vuln_type: str) -> str:
    raw = f"{target}:{vuln_type}:{datetime.now().isoformat()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _build_retrieval_text(vuln_type, web_server, owasp, steps, findings) -> str:
    """
    Build a single text string used for semantic similarity search.
    This is what gets embedded into the FAISS vector index.
    """
    parts = [
        f"vulnerability: {vuln_type}",
        f"server: {web_server}",
        f"owasp: {owasp}",
        f"steps: {' '.join([s.get('tool','') for s in steps])}",
        f"findings: {' '.join([str(f)[:100] for f in findings])}",
    ]
    return " | ".join(parts)


# ─────────────────────────────────────────────────────────────
# EKB STORAGE CLASS
# ─────────────────────────────────────────────────────────────

class ExperienceKnowledgeBase:
    """
    The EKB stores and retrieves past exploit experiences.

    Phase 2 implementation:
    - JSON file storage (one file per experience)
    - FAISS vector index for fast semantic search
    - Keyword fallback if sentence-transformers not installed
    - 3-layer memory architecture from Co-RedTeam paper

    CurriculumPT results showed:
    - EHR (Experience Hit Rate) = 80% on hold-out set
    - Removing EKB drops complex ESR from 60% → 43.3%
    """

    def __init__(self, ekb_dir: str = "memory/ekb"):
        self.ekb_dir   = Path(ekb_dir)
        self.ekb_dir.mkdir(parents=True, exist_ok=True)

        self.index_file = self.ekb_dir / "index.json"
        self.entries    = self._load_index()

        # Try to load FAISS + sentence-transformers
        self.faiss_available = False
        self.embedder        = None
        self.faiss_index     = None
        self.faiss_ids       = []  # Maps FAISS index position → entry id

        self._init_faiss()

        print(f"[EKB] 📚 Initialized. Entries: {len(self.entries)}, FAISS: {self.faiss_available}")

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def store(self, entry: dict) -> str:
        """
        Store a new experience in the EKB.
        Returns the entry ID.

        Based on CurriculumPT Report Agent: stores after every task
        regardless of success or failure.
        """
        entry_id = entry["id"]

        # Save JSON file
        filepath = self.ekb_dir / f"{entry_id}.json"
        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2)

        # Add to in-memory index
        self.entries[entry_id] = {
            "id":            entry_id,
            "vuln_type":     entry["vuln_type"],
            "owasp":         entry["owasp_category"],
            "difficulty":    entry["difficulty"],
            "success":       entry["success"],
            "web_server":    entry["web_server"],
            "retrieval_text": entry["retrieval_text"],
            "timestamp":     entry["timestamp"],
            "filepath":      str(filepath),
        }

        # Update FAISS index if available
        if self.faiss_available:
            self._add_to_faiss(entry_id, entry["retrieval_text"])

        # Save updated index
        self._save_index()

        status = "✅ success" if entry["success"] else "❌ failure"
        print(f"[EKB] 💾 Stored [{status}]: {entry['vuln_type']} on {entry['web_server']} (id: {entry_id})")
        return entry_id

    def retrieve(self, query: str, top_k: int = 3, success_only: bool = False) -> list[dict]:
        """
        Retrieve top-k most relevant experiences for a given query.

        query: description of current task (e.g. "SQL injection on Apache login page")
        top_k: number of results to return (MultiVer uses k=5, we default to 3)
        success_only: if True, only return successful exploits

        Based on:
        - PentestMCP: cosine similarity ≥ 0.90 for RAG matching
        - CurriculumPT: semantic query over EKB before planning
        - MultiVer: FAISS k=5 retrieval
        """
        if not self.entries:
            return []

        candidates = list(self.entries.values())
        if success_only:
            candidates = [e for e in candidates if e.get("success")]

        if not candidates:
            return []

        # Use FAISS if available
        if self.faiss_available and self.faiss_index and len(self.faiss_ids) > 0:
            results = self._faiss_search(query, top_k, candidates)
        else:
            # Keyword fallback
            results = self._keyword_search(query, top_k, candidates)

        # Load full entry data for each result
        full_results = []
        for meta in results:
            full = self._load_entry(meta["id"])
            if full:
                full["similarity_score"] = meta.get("score", 0.0)
                full_results.append(full)

        return full_results

    def get_stats(self) -> dict:
        """Return EKB statistics."""
        entries = list(self.entries.values())
        successful = [e for e in entries if e.get("success")]

        vuln_counts = {}
        for e in entries:
            vt = e.get("vuln_type", "Unknown")
            vuln_counts[vt] = vuln_counts.get(vt, 0) + 1

        return {
            "total_entries":      len(entries),
            "successful_entries": len(successful),
            "failed_entries":     len(entries) - len(successful),
            "success_rate":       len(successful) / max(len(entries), 1),
            "vuln_type_counts":   vuln_counts,
            "faiss_available":    self.faiss_available,
            "ekb_dir":            str(self.ekb_dir),
        }

    def format_for_planner(self, experiences: list[dict]) -> str:
        """
        Format retrieved experiences into a prompt-ready string
        for injection into the Planner Agent context.

        Based on CurriculumPT prompt template:
        "You are trying to exploit [target]. According to the experience base,
         a similar vulnerability was successfully exploited using: [steps]"
        """
        if not experiences:
            return ""

        lines = ["RELEVANT PAST EXPERIENCES FROM KNOWLEDGE BASE:"]
        lines.append("=" * 50)

        for i, exp in enumerate(experiences, 1):
            score = exp.get("similarity_score", 0.0)
            lines.append(f"\n[Experience {i}] (Similarity: {score:.2f})")
            lines.append(f"  Vulnerability:  {exp.get('vuln_type', '?')}")
            lines.append(f"  Web Server:     {exp.get('web_server', '?')}")
            lines.append(f"  OWASP:          {exp.get('owasp_category', '?')}")
            lines.append(f"  Difficulty:     {exp.get('difficulty', '?')}")
            lines.append(f"  Result:         {'✅ SUCCESS' if exp.get('success') else '❌ FAILED'}")

            if exp.get("injectable_params"):
                lines.append(f"  Params tested:  {exp['injectable_params']}")

            if exp.get("findings"):
                lines.append(f"  Key findings:")
                for f in exp["findings"][:3]:
                    lines.append(f"    • {str(f)[:120]}")

            if exp.get("steps"):
                lines.append(f"  Steps used ({len(exp['steps'])} total):")
                for s in exp["steps"][:4]:
                    tool = s.get("tool", s.get("name", "?"))
                    lines.append(f"    → {tool}")

            if exp.get("notes"):
                lines.append(f"  Notes:          {exp['notes'][:150]}")

        lines.append("\n" + "=" * 50)
        lines.append("Use these experiences to improve your exploitation plan.")

        return "\n".join(lines)

    # ──────────────────────────────────────────────
    # FAISS SETUP
    # ──────────────────────────────────────────────

    def _init_faiss(self):
        """Initialize FAISS index and sentence embedder."""
        try:
            import faiss
            from sentence_transformers import SentenceTransformer

            # all-MiniLM-L6-v2 — same model used in PentestMCP paper
            print("[EKB] 🔄 Loading sentence embedder (all-MiniLM-L6-v2)...")
            self.embedder = SentenceTransformer("all-MiniLM-L6-v2")

            dim = 384  # all-MiniLM-L6-v2 output dimension
            self.faiss_index = faiss.IndexFlatIP(dim)  # Inner product = cosine on normalized vectors

            # Load existing entries into FAISS
            if self.entries:
                print(f"[EKB] 🔄 Indexing {len(self.entries)} existing entries into FAISS...")
                for entry_id, meta in self.entries.items():
                    self._add_to_faiss(entry_id, meta["retrieval_text"])

            self.faiss_available = True
            print(f"[EKB] ✅ FAISS ready ({self.faiss_index.ntotal} vectors)")

        except ImportError:
            print("[EKB] ⚠️  FAISS/sentence-transformers not installed — using keyword search")
            print("[EKB]     Install with: pip install faiss-cpu sentence-transformers")
            self.faiss_available = False

    def _add_to_faiss(self, entry_id: str, text: str):
        """Embed text and add to FAISS index."""
        try:
            import numpy as np
            vec = self.embedder.encode([text], normalize_embeddings=True)
            self.faiss_index.add(vec.astype("float32"))
            self.faiss_ids.append(entry_id)
        except Exception as e:
            print(f"[EKB] ⚠️  FAISS add error: {e}")

    def _faiss_search(self, query: str, top_k: int, candidates: list) -> list:
        """Search FAISS index for most similar entries."""
        try:
            import numpy as np
            vec   = self.embedder.encode([query], normalize_embeddings=True)
            k     = min(top_k, self.faiss_index.ntotal)
            scores, indices = self.faiss_index.search(vec.astype("float32"), k)

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.faiss_ids):
                    entry_id = self.faiss_ids[idx]
                    if entry_id in self.entries:
                        meta = self.entries[entry_id].copy()
                        meta["score"] = float(score)
                        results.append(meta)

            return results
        except Exception as e:
            print(f"[EKB] ⚠️  FAISS search error: {e} — falling back to keyword")
            return self._keyword_search(query, top_k, candidates)

    # ──────────────────────────────────────────────
    # KEYWORD FALLBACK SEARCH
    # ──────────────────────────────────────────────

    def _keyword_search(self, query: str, top_k: int, candidates: list) -> list:
        """
        Simple keyword overlap search when FAISS is unavailable.
        Scores entries by how many query terms appear in retrieval_text.
        """
        query_terms = set(re.sub(r"[^\w\s]", "", query.lower()).split())

        scored = []
        for meta in candidates:
            text  = meta.get("retrieval_text", "").lower()
            score = sum(1 for term in query_terms if term in text)
            # Bonus: exact vuln type match
            if meta.get("vuln_type", "").lower() in query.lower():
                score += 3
            scored.append({**meta, "score": score})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    # ──────────────────────────────────────────────
    # PERSISTENCE
    # ──────────────────────────────────────────────

    def _load_index(self) -> dict:
        """Load the EKB index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_index(self):
        """Save the EKB index to disk."""
        with open(self.index_file, "w") as f:
            json.dump(self.entries, f, indent=2)

    def _load_entry(self, entry_id: str) -> Optional[dict]:
        """Load a full entry from its JSON file."""
        meta = self.entries.get(entry_id)
        if not meta:
            return None
        try:
            with open(meta["filepath"]) as f:
                return json.load(f)
        except Exception:
            return None
