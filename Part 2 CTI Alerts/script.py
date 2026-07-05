"""
script.py  –  Backward-compatible entry point.
───────────────────────────────────────────────
  run_pipeline.py     ← orchestrator
  config.py           ← paths, constants, knowledge base, LLM settings
  alert_generator.py  ← Section 1: alert generation
  llm_enricher.py     ← Section 2: LLM enrichment
  evaluator.py        ← Section 3: output evaluation
  report_writer.py    ← Section 4: incident report

"""

from run_pipeline import main

if __name__ == "__main__":
    main()
