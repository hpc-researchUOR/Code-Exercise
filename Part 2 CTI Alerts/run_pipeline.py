"""
run_pipeline.py
───────────────
  1. alert_generator  
  2. llm_enricher    
  3. evaluator       
  4. report_writer   

Usage
─────
  python "Part 2 CTI Alerts/run_pipeline.py"

Prerequisites
─────────────
  pip install joblib numpy pandas requests xgboost

  For LLM enrichment (optional but recommended):
    1. Install Ollama  →  https://ollama.com
    2. ollama pull qwen2.5:0.5b
    3. ollama serve
"""

import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

import config
import alert_generator
import llm_enricher
import evaluator
import report_writer


def main() -> None:
    _banner()

    # Ensure output directories exist before any module runs
    for d in (config.ALERTS_DIR, config.REPORTS_DIR, config.EVAL_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # ── Section 1: Alert Generation ──────────────────────────────────────────
    model, label_encoder, scaler, test_df, src_encoder, dst_encoder = alert_generator.load_artifacts()
    samples, feature_cols = alert_generator.select_samples(test_df, n=config.N_SAMPLES)
    alerts = alert_generator.generate_alerts(model, samples, feature_cols, scaler=scaler, src_encoder=src_encoder, dst_encoder=dst_encoder)

    # ── Section 2: LLM Enrichment ────────────────────────────────────────────
    reports = llm_enricher.enrich_alerts(alerts)

    # ── Section 3: Evaluation ────────────────────────────────────────────────
    eval_rows = evaluator.evaluate_reports(alerts, reports)

    # ── Section 4: Incident Report ───────────────────────────────────────────
    report_path = report_writer.generate_incident_report(alerts, reports, eval_rows)

    _summary(report_path)


# Formatting helpers

def _banner() -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 60)
    print("  CTI Alert Generation & LLM Enrichment Pipeline")
    print(f"  {now}")
    print("=" * 60)


def _summary(report_path) -> None:
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print(f"  Alerts     : {config.ALERTS_DIR}")
    print(f"  Reports    : {config.REPORTS_DIR}")
    print(f"  Evaluation : {config.EVAL_DIR / 'evaluation_summary.csv'}")
    print(f"  Incident   : {report_path}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
