"""
alert_generator.py
──────────────────
Section 1 – Structured CTI Alert Generation.

Responsibilities:
  • Load the trained XGBoost model and test dataset.
  • Select a representative set of samples (one per attack class).
  • Run inference (predict_proba) to get full probability distributions.
  • Build a structured JSON CTI alert for each sample.
  • Save each alert to ALERTS_DIR.

"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import config



# Artifact loading

def load_artifacts() -> tuple:
    """
    Load and return:
        model         – trained XGBoost classifier
        label_encoder – sklearn LabelEncoder (or None)
        scaler        – RobustScaler (or None)
        test_df       – raw test DataFrame
    """
    print("=" * 60)
    print("SECTION 1: Loading model and test data …")

    if not config.MODEL_PATH.exists():
        sys.exit(f"[ERROR] Model not found: {config.MODEL_PATH}")
    model = joblib.load(config.MODEL_PATH)
    print(f"  ✔ Model loaded:   {config.MODEL_PATH.name}")

    label_encoder = None
    if config.ENCODER_PATH.exists():
        label_encoder = joblib.load(config.ENCODER_PATH)
        print(f"  ✔ Encoder loaded: {config.ENCODER_PATH.name}")
    else:
        print(f"  ⚠ Encoder not found at {config.ENCODER_PATH} – using built-in class map.")

    scaler = None
    if config.SCALER_PATH.exists():
        scaler = joblib.load(config.SCALER_PATH)
        print(f"  ✔ Scaler loaded:  {config.SCALER_PATH.name}")

    if not config.TEST_CSV.exists():
        sys.exit(f"[ERROR] Test CSV not found: {config.TEST_CSV}")
    test_df = pd.read_csv(config.TEST_CSV)
    print(f"  ✔ Test data:      {len(test_df):,} rows")

    return model, label_encoder, scaler, test_df


# Sample selection

def select_samples(test_df: pd.DataFrame, n: int = config.N_SAMPLES) -> tuple[pd.DataFrame, list[str]]:
    """
    Select `n` representative rows – at least one from each attack class,
    padded with benign rows.

    Returns:
        samples      – selected DataFrame (reset index)
        feature_cols – list of feature column names (excludes label columns)
    """
    feature_cols = [
        c for c in test_df.columns
        if c not in ("Attack Type", "Attack Type_encoded")
    ]

    chosen = []
    # Prioritise one sample per non-benign class
    for cls in [1, 2, 3]:
        subset = test_df[test_df["Attack Type_encoded"] == cls]
        if not subset.empty:
            chosen.append(subset.sample(1, random_state=42 + cls))

    # Pad with benign rows if needed
    remaining = n - len(chosen)
    benign = test_df[test_df["Attack Type_encoded"] == 0]
    if not benign.empty and remaining > 0:
        chosen.append(benign.sample(min(remaining, len(benign)), random_state=99))

    samples = pd.concat(chosen).head(n).reset_index(drop=True)

    print(f"\n  Selected {len(samples)} samples:")
    for _, row in samples.iterrows():
        lbl = config.CLASS_NAMES.get(int(row["Attack Type_encoded"]), "Unknown")
        print(f"    class={int(row['Attack Type_encoded'])} ({lbl})")

    return samples, feature_cols



# Alert construction helpers

# Feature keys to include in the network_observations field
_OBSERVATION_KEYS = [
    "packet_length", "src_ip", "dst_ip",
    "src_port", "dst_port",
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "fwd_packet_length_mean", "bwd_packet_length_mean",
    "flow_bytes_per_s", "flow_packets_per_s",
    "is_tcp", "is_udp", "is_icmp",
]


def _network_component(row: pd.Series) -> dict:
    """Derive the affected network component description from feature values."""
    proto = "unknown"
    if row.get("is_tcp", 0) == 1:
        proto = "TCP"
    elif row.get("is_udp", 0) == 1:
        proto = "UDP"
    elif row.get("is_icmp", 0) == 1:
        proto = "ICMP"

    src = row.get("src_ip", "N/A")
    dst = row.get("dst_ip", "N/A")

    return {
        "source_ip":      str(src),
        "destination_ip": str(dst),
        "protocol":       proto,
        "description":    f"Network flow from {src} to {dst} over {proto}",
    }


def _network_observations(row: pd.Series) -> dict:
    """Extract a curated subset of feature values for the alert."""
    obs = {}
    for key in _OBSERVATION_KEYS:
        if key in row.index:
            val = row[key]
            if isinstance(val, (float, np.floating)):
                val = round(float(val), 4)
            elif isinstance(val, (int, np.integer)):
                val = int(val)
            else:
                val = str(val)
            obs[key] = val
    return obs


def _alternative_predictions(probabilities: np.ndarray, pred_class: int) -> list[dict]:
    """Build a ranked list of non-top-class predictions."""
    alts = [
        {
            "class_id":    cls_idx,
            "class_name":  config.CLASS_NAMES.get(cls_idx, f"Class_{cls_idx}"),
            "probability": round(float(prob), 6),
        }
        for cls_idx, prob in enumerate(probabilities)
        if cls_idx != pred_class
    ]
    alts.sort(key=lambda x: x["probability"], reverse=True)
    return alts



# Public API
def build_alert(
    row:           pd.Series,
    probabilities: np.ndarray,
    feature_cols:  list[str],
    sample_idx:    int,
) -> dict:
    """
    Build and return one structured CTI alert dict.

    Required fields (per assignment specification):
      Predicted threat class
      Prediction confidence
      Alternative predictions
      Relevant network observations
      Affected network component
      Detection timestamp

    The true label is NOT included in the returned dict.
    """
    pred_class = int(np.argmax(probabilities))
    confidence = float(np.max(probabilities))

    return {
        "alert_id":            str(uuid.uuid4()),
        "schema_version":      "1.0",
        "detection_timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_index":        sample_idx,

        "model_metadata": {
            "model_type":        "XGBoostClassifier",
            "model_version":     "xgboost_best_model",
            "training_f1_macro": 0.890,
            "num_classes":       len(config.CLASS_NAMES),
            "feature_count":     len(feature_cols),
        },

        "predicted_threat": {
            "class_id":      pred_class,
            "class_name":    config.CLASS_NAMES.get(pred_class, f"Class_{pred_class}"),
            "confidence":    round(confidence, 6),
            "confidence_pct": f"{confidence * 100:.2f}%",
        },

        "alternative_predictions":   _alternative_predictions(probabilities, pred_class),
        "network_observations":      _network_observations(row),
        "affected_network_component": _network_component(row),
    }


def generate_alerts(
    model:        object,
    samples:      pd.DataFrame,
    feature_cols: list[str],
    scaler:       object = None,
) -> list[dict]:
    """
    Run inference on all samples, build alert objects, persist them to disk.

    Returns:
        List of alert dicts (also saved as JSON under ALERTS_DIR).
    """
    config.ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    print("\n  Generating structured CTI alerts …")

    X = samples[feature_cols]
    X_pred = X.copy()
    
    # XGBoost relies on exact feature name and order
    if hasattr(model, "feature_names_in_"):
        X_pred = X_pred[model.feature_names_in_]
        
    prob_matrix = model.predict_proba(X_pred)   # shape (n_samples, n_classes)

    alerts = []
    for i, (_, row) in enumerate(samples.iterrows()):
        alert = build_alert(row, prob_matrix[i], feature_cols, sample_idx=i)
        short = alert["alert_id"][:8]
        path  = config.ALERTS_DIR / f"alert_{short}.json"
        path.write_text(json.dumps(alert, indent=2), encoding="utf-8")
        alerts.append(alert)

        cls  = alert["predicted_threat"]["class_name"]
        conf = alert["predicted_threat"]["confidence_pct"]
        print(f"    [alert {i+1}] {cls:11s}  conf={conf}  → {path.name}")

    print(f"  ✔ {len(alerts)} alerts saved to {config.ALERTS_DIR}")
    return alerts
