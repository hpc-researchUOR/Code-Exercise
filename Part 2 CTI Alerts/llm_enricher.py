"""
llm_enricher.py
───────────────
Section 2 – LLM-Based CTI Enrichment.

Responsibilities:
  • Check whether the Ollama REST API is reachable.
  • Build a two-part prompt (system + user) for each alert.
  • Call the Ollama /api/generate endpoint (qwen2.5:0.5b by default).
  • Measure wall-clock generation time per request.
  • Parse and validate the LLM's JSON response.
  • Fall back gracefully to heuristic placeholders when Ollama is unavailable.
  • Persist each enriched report to REPORTS_DIR.

LLM Model: qwen2.5:0.5b (Qwen 2.5 series, ~400 MB, offline, zero cost)
Deployment: Ollama  – https://ollama.com
"""

import json
import time
import uuid
from datetime import datetime, timezone

import requests

import config


# ─────────────────────────────────────────────────────────────────────────────
# Ollama connectivity
# ─────────────────────────────────────────────────────────────────────────────

def check_ollama() -> bool:
    """Return True if the Ollama REST API is reachable and responsive."""
    try:
        r = requests.get(f"{config.OLLAMA_BASE_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def _print_ollama_instructions() -> None:
    print(f"\n  ⚠  Ollama not reachable at {config.OLLAMA_BASE_URL}")
    print("     To enable LLM enrichment:")
    print("       1. Install Ollama  →  https://ollama.com")
    print(f"       2. ollama pull {config.LLM_MODEL}")
    print("       3. ollama serve")
    print("     Continuing with heuristic placeholders …\n")


# ─────────────────────────────────────────────────────────────────────────────
# Prompt construction
# ─────────────────────────────────────────────────────────────────────────────

def build_user_prompt(alert: dict) -> str:
    """
    Build the per-alert user message:
      - Injects the class-specific threat knowledge (grounding)
      - Appends the alert JSON
      - Gives the task instruction
    """
    cls_name  = alert["predicted_threat"]["class_name"]
    knowledge = config.THREAT_KNOWLEDGE.get(cls_name, "No specific knowledge available.")
    alert_json = json.dumps(alert, indent=2)

    return (
        f"=== THREAT KNOWLEDGE ===\n"
        f"Threat type: {cls_name}\n"
        f"{knowledge}\n\n"
        f"=== CTI ALERT ===\n"
        f"{alert_json}\n\n"
        f"=== TASK ===\n"
        f"Analyse the alert above using only the provided knowledge and alert data. "
        f"Produce the structured CTI enrichment report in the specified JSON format."
    )


def _full_prompt(alert: dict) -> str:
    """Combine system and user prompts into a single string for Ollama."""
    return f"{config.SYSTEM_PROMPT}\n\n{build_user_prompt(alert)}"


# ─────────────────────────────────────────────────────────────────────────────
# Ollama API call
# ─────────────────────────────────────────────────────────────────────────────

def _call_ollama(prompt: str) -> tuple[str, float]:
    """
    POST to the Ollama generate endpoint.

    Returns:
        (response_text, elapsed_seconds)

    Raises:
        requests.HTTPError on non-2xx responses.
    """
    payload = {
        "model":  config.LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": config.LLM_TEMPERATURE,
            "top_p":       0.9,
            "num_predict": config.LLM_MAX_TOKENS,
        },
    }
    t0 = time.perf_counter()
    response = requests.post(
        f"{config.OLLAMA_BASE_URL}/api/generate",
        json=payload,
        timeout=config.LLM_TIMEOUT_S,
    )
    elapsed = time.perf_counter() - t0
    response.raise_for_status()
    return response.json().get("response", ""), elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Response parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_llm_response(raw: str) -> dict:
    """
    Extract the JSON object from the LLM's raw response text.
    Handles prose before/after the JSON block.

    Returns a dict — wraps raw text in {"raw_response": ..., "parse_error": True}
    if parsing fails entirely.
    """
    # Direct parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Find the first '{' … last '}' pair
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(raw[start:end])
        except json.JSONDecodeError:
            pass

    return {"raw_response": raw, "parse_error": True}


# ─────────────────────────────────────────────────────────────────────────────
# Fallback heuristics (used when Ollama is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

_HEURISTIC_SEVERITY: dict[str, str] = {
    "Benign":     "INFORMATIONAL",
    "BruteForce": "HIGH",
    "DoS":        "HIGH",
    "DDoS":       "CRITICAL",
}


def _heuristic_enrichment(cls_name: str) -> dict:
    """Return a clearly labelled placeholder when LLM is not available."""
    severity = _HEURISTIC_SEVERITY.get(cls_name, "MEDIUM")
    return {
        "threat_context":             f"[Heuristic – LLM unavailable] Detected {cls_name} traffic.",
        "attack_correlation":         "N/A – Ollama not running",
        "severity":                   severity,
        "severity_justification":     "Heuristic fallback; no LLM available",
        "possible_impact":            "N/A",
        "immediate_response":         "N/A",
        "long_term_mitigation":       "N/A",
        "human_review_required":      "YES" if cls_name != "Benign" else "NO",
        "human_review_justification": "Heuristic: all non-benign alerts require review",
        "_llm_meta": {
            "model":             config.LLM_MODEL,
            "generation_time_s": None,
            "ollama_available":  False,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def enrich_single_alert(alert: dict, ollama_ok: bool) -> dict:
    """
    Enrich one alert with LLM analysis.

    Returns:
        enrichment dict (real LLM output or heuristic placeholder).
    """
    cls_name = alert["predicted_threat"]["class_name"]

    if not ollama_ok:
        return _heuristic_enrichment(cls_name)

    try:
        raw, elapsed = _call_ollama(_full_prompt(alert))
        enrichment   = parse_llm_response(raw)
        enrichment["_llm_meta"] = {
            "model":             config.LLM_MODEL,
            "generation_time_s": round(elapsed, 2),
            "ollama_available":  True,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }
        return enrichment
    except Exception as exc:
        return {
            "error": str(exc),
            "_llm_meta": {
                "model":             config.LLM_MODEL,
                "generation_time_s": None,
                "ollama_available":  True,
                "error":             str(exc),
                "timestamp":         datetime.now(timezone.utc).isoformat(),
            },
        }


def enrich_alerts(alerts: list[dict]) -> list[dict]:
    """
    Enrich every alert in the list and persist each report to REPORTS_DIR.

    Returns:
        List of report dicts (one per alert).
    """
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 60)
    print("SECTION 2: LLM Enrichment …")

    ollama_ok = check_ollama()
    if not ollama_ok:
        _print_ollama_instructions()

    reports = []
    for i, alert in enumerate(alerts):
        short    = alert["alert_id"][:8]
        cls_name = alert["predicted_threat"]["class_name"]
        print(f"  [{i+1}/{len(alerts)}] Enriching {short} ({cls_name}) …", end="", flush=True)

        enrichment = enrich_single_alert(alert, ollama_ok)

        meta     = enrichment.get("_llm_meta", {})
        gen_time = meta.get("generation_time_s")
        suffix   = f" done in {gen_time:.1f}s" if gen_time else " (placeholder)"
        print(suffix)

        report = {
            "report_id":   str(uuid.uuid4()),
            "alert_id":    alert["alert_id"],
            "alert_summary": {
                "predicted_class": cls_name,
                "confidence":      alert["predicted_threat"]["confidence"],
                "detection_ts":    alert["detection_timestamp"],
            },
            "llm_enrichment": enrichment,
        }

        path = config.REPORTS_DIR / f"report_{short}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        reports.append(report)

    print(f"\n  ✔ {len(reports)} reports saved to {config.REPORTS_DIR}")
    return reports
