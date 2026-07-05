"""
evaluator.py
────────────
Section 3 – LLM Output Evaluation.

Responsibilities:
  • Check whether the LLM's threat description matches the detected attack class.
  • Assess whether the assigned severity is reasonable for the predicted class.
  • Detect hallucinations: IP addresses in LLM text that were not in the alert.
  • Measure LLM generation time (sourced from _llm_meta stored in the report).
  • Write evaluation_summary.csv to EVAL_DIR.
  • Print a human-readable per-alert summary to stdout.
"""

import csv
import re
from pathlib import Path

import config


# ─────────────────────────────────────────────────────────────────────────────
# Individual checks
# ─────────────────────────────────────────────────────────────────────────────

# Keyword synonyms used for threat-match checking
_CLASS_KEYWORDS: dict[str, list[str]] = {
    "Benign":     ["benign", "normal", "legitimate", "no threat"],
    "BruteForce": ["brute", "brute-force", "bruteforce", "credential", "authentication"],
    "DoS":        ["denial", "dos", "flood", "exhaust", "overwhelm"],
    "DDoS":       ["distributed", "ddos", "botnet", "amplification"],
}

# Pattern to find IPv4 addresses in text
_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def check_threat_match(predicted_class: str, enrichment: dict) -> bool:
    """
    Return True if the LLM's enrichment text contains at least one keyword
    associated with the predicted class.

    Searches across all non-metadata string fields in the enrichment dict.
    """
    keywords  = _CLASS_KEYWORDS.get(predicted_class, [predicted_class.lower()])
    llm_text  = " ".join(
        str(v)
        for k, v in enrichment.items()
        if not k.startswith("_") and k not in ("parse_error", "raw_response")
    ).lower()
    return any(kw in llm_text for kw in keywords)


def detect_hallucinations(alert: dict, enrichment: dict) -> list[str]:
    """
    Return a list of hallucination descriptions found in the LLM output.

    Currently detects: IP addresses mentioned by the LLM that do not appear
    anywhere in the alert's network_observations or affected_network_component.
    """
    # Collect all IP-like strings that were actually in the alert
    alert_values: set[str] = set()

    for v in alert.get("network_observations", {}).values():
        alert_values.add(str(v))

    comp = alert.get("affected_network_component", {})
    alert_values.update([
        str(comp.get("source_ip", "")),
        str(comp.get("destination_ip", "")),
        str(comp.get("protocol", "")),
    ])

    # Add class names so the LLM isn't penalised for naming them
    alert_values.update(config.CLASS_NAMES.values())
    alert_values.discard("N/A")

    # Scan LLM text for IP addresses not in the alert
    llm_text = " ".join(
        str(v)
        for k, v in enrichment.items()
        if not k.startswith("_") and k not in ("parse_error", "raw_response")
    )

    hallucinations = []
    for ip in set(_IP_PATTERN.findall(llm_text)):
        if ip not in alert_values:
            hallucinations.append(f"Invented IP: {ip}")

    return hallucinations


def check_severity(predicted_class: str, enrichment: dict) -> tuple[str, bool]:
    """
    Return (severity_string, is_reasonable).

    Reasonable is defined as: the severity falls within the expected range
    for the predicted class (see config.EXPECTED_SEVERITY).
    """
    severity = str(enrichment.get("severity", "UNKNOWN")).upper()
    expected = config.EXPECTED_SEVERITY.get(predicted_class, config.VALID_SEVERITIES)
    return severity, severity in expected


# ─────────────────────────────────────────────────────────────────────────────
# CSV field definitions
# ─────────────────────────────────────────────────────────────────────────────

_CSV_FIELDS = [
    "alert_id",
    "predicted_class",
    "confidence",
    "severity_assigned",
    "severity_reasonable",
    "threat_match",
    "hallucination_count",
    "hallucinations",
    "generation_time_s",
    "llm_available",
    "human_review_required",
]


# ─────────────────────────────────────────────────────────────────────────────
# Console formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _icon(flag: bool) -> str:
    return "✔" if flag else "✘"


def _print_alert_eval(alert: dict, row: dict) -> None:
    print(f"  Alert {alert['alert_id'][:8]}  [{row['predicted_class']:11s}]")
    print(f"    Confidence     : {float(row['confidence']) * 100:.1f}%")
    print(f"    Severity       : {row['severity_assigned']}  {_icon(row['severity_reasonable'])}")
    print(f"    Threat match   : {_icon(row['threat_match'])}")

    h_count = row["hallucination_count"]
    if h_count == 0:
        print(f"    Hallucinations : ✔")
    else:
        print(f"    Hallucinations : ⚠ ({h_count})")
        for h in row["hallucinations"].split("; "):
            if h and h != "none":
                print(f"      ↳ {h}")

    gen = row["generation_time_s"]
    if gen != "N/A":
        print(f"    Gen time       : {gen}s")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_reports(alerts: list[dict], reports: list[dict]) -> list[dict]:
    """
    Evaluate all LLM enrichment reports and persist results.

    For each (alert, report) pair:
      - Runs threat_match, severity, hallucination checks
      - Prints a human-readable summary
      - Collects a result row

    Writes evaluation_summary.csv to EVAL_DIR and returns the list of row dicts.
    """
    config.EVAL_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 60)
    print("SECTION 3: Evaluating LLM reports …\n")

    rows = []
    for alert, report in zip(alerts, reports):
        enrichment    = report.get("llm_enrichment", {})
        meta          = enrichment.get("_llm_meta", {})
        predicted_cls = alert["predicted_threat"]["class_name"]
        confidence    = alert["predicted_threat"]["confidence"]

        severity, sev_ok   = check_severity(predicted_cls, enrichment)
        threat_match       = check_threat_match(predicted_cls, enrichment)
        hallucinations     = detect_hallucinations(alert, enrichment)
        gen_time           = meta.get("generation_time_s")

        row = {
            "alert_id":           alert["alert_id"],
            "predicted_class":    predicted_cls,
            "confidence":         f"{confidence:.4f}",
            "severity_assigned":  severity,
            "severity_reasonable": sev_ok,
            "threat_match":       threat_match,
            "hallucination_count": len(hallucinations),
            "hallucinations":     "; ".join(hallucinations) if hallucinations else "none",
            "generation_time_s":  gen_time if gen_time is not None else "N/A",
            "llm_available":      meta.get("ollama_available", False),
            "human_review_required": enrichment.get("human_review_required", "N/A"),
        }
        rows.append(row)
        _print_alert_eval(alert, row)

    eval_path = config.EVAL_DIR / "evaluation_summary.csv"
    with open(eval_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✔ Evaluation saved to {eval_path}")
    return rows
