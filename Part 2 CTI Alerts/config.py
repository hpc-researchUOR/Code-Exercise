"""
config.py
─────────
Central configuration for the Part 2 CTI Alert pipeline.
Edit this file to change paths, LLM settings, or the threat knowledge base.
"""

from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
_HERE  = Path(__file__).resolve().parent        # …/Part 2 CTI Alerts/
_ROOT  = _HERE.parent                           # …/Coding Assignment/

MODEL_PATH   = _ROOT / "Model Developing/saved/models/xgboost_best_model.pkl"
ENCODER_PATH = _ROOT / "saved/label_encoder.pkl"
SCALER_PATH  = _ROOT / "saved/robust_scaler.pkl"
SRC_ENCODER_PATH = _ROOT / "saved/src_encoder.pkl"
DST_ENCODER_PATH = _ROOT / "saved/dst_encoder.pkl"
TEST_CSV    = _ROOT / "test_set.csv"

# Output directories (created automatically at runtime)
ALERTS_DIR  = _HERE / "alerts"
REPORTS_DIR = _HERE / "reports"
EVAL_DIR    = _HERE / "evaluation"

# ─────────────────────────────────────────────────────────────────────────────
# Dataset / model constants
# ─────────────────────────────────────────────────────────────────────────────

# Integer-to-name mapping confirmed from project folder names
CLASS_NAMES: dict[int, str] = {
    0: "Benign",
    1: "BruteForce",
    2: "DoS",
    3: "DDoS",
}

# Number of samples to process end-to-end
N_SAMPLES: int = 5

# ─────────────────────────────────────────────────────────────────────────────
# LLM settings  (Ollama, local)
# ─────────────────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL: str = "http://localhost:11434"
LLM_MODEL:       str = "qwen2.5:0.5b"   # ~400 MB, offline, no API key needed
LLM_TEMPERATURE: float = 0.2            # low = factual output
LLM_MAX_TOKENS:  int   = 512
LLM_TIMEOUT_S:   int   = 120

# ─────────────────────────────────────────────────────────────────────────────
# Threat knowledge base  (injected into every LLM prompt)
# Grounded facts only — prevents the LLM from inventing attack details.
# ─────────────────────────────────────────────────────────────────────────────
THREAT_KNOWLEDGE: dict[str, str] = {
    "Benign": (
        "Benign traffic represents normal, legitimate network communication. "
        "No malicious indicators are expected."
    ),
    "BruteForce": (
        "Brute-force attacks (MITRE ATT&CK T1110) involve repeated, rapid "
        "authentication attempts against a service (SSH, FTP, RDP, HTTP). "
        "Indicators include: high packet rate from a single source IP, "
        "repeated small TCP packets, high failed login counts. "
        "Common tools: Hydra, Medusa, Ncrack."
    ),
    "DoS": (
        "Denial-of-Service attacks (MITRE ATT&CK T1498/T1499) aim to exhaust "
        "server resources from a single source. Indicators include: abnormally "
        "high flow bytes/s, large packet sizes, SYN flood patterns, or HTTP "
        "floods. Techniques: Slowloris, SYN flood, UDP flood."
    ),
    "DDoS": (
        "Distributed Denial-of-Service attacks (MITRE ATT&CK T1498) originate "
        "from multiple sources (botnet). High aggregate bandwidth, multiple "
        "source IPs, and amplification patterns (DNS, NTP, SSDP) are typical. "
        "Impact is significantly higher than single-source DoS."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# LLM system prompt
# ─────────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT: str = """\
You are a Cyber Threat Intelligence (CTI) analyst. You will be given a structured \
machine-learning-generated network intrusion alert in JSON format, along with \
relevant threat knowledge.

Your task is to produce a structured CTI enrichment report. You must:
1. Contextualise the detected threat based ONLY on the alert data and knowledge provided.
2. Correlate the network observations with known attack behaviour.
3. Assign a severity level: INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL.
4. Describe the possible impact on the affected component.
5. Recommend an immediate response action.
6. Suggest a longer-term mitigation strategy.
7. State whether human review is required (YES / NO) and justify why.

STRICT RULES:
- Do NOT invent IP addresses, ports, or indicators that are not in the alert.
- Do NOT reference tools or techniques unless corroborated by the alert data.
- Base all statements on the provided alert and knowledge only.
- Keep your response concise and structured.

Respond ONLY in the following JSON format:
{
  "threat_context": "<1-3 sentence contextualisation>",
  "attack_correlation": "<what known behaviour this matches>",
  "severity": "<INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL>",
  "severity_justification": "<brief reason>",
  "possible_impact": "<impact description>",
  "immediate_response": "<action to take now>",
  "long_term_mitigation": "<strategic mitigation>",
  "human_review_required": "<YES|NO>",
  "human_review_justification": "<brief reason>"
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Evaluation constants
# ─────────────────────────────────────────────────────────────────────────────

# Severity values considered reasonable for each class
EXPECTED_SEVERITY: dict[str, set] = {
    "Benign":     {"INFORMATIONAL", "LOW"},
    "BruteForce": {"MEDIUM", "HIGH", "CRITICAL"},
    "DoS":        {"HIGH", "CRITICAL"},
    "DDoS":       {"HIGH", "CRITICAL"},
}

VALID_SEVERITIES: set[str] = {
    "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
}
