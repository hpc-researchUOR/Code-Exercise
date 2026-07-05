# LLM-Assisted Cyber Threat Intelligence for 5G O-RAN Security

## Overview

This repository contains an end-to-end framework for **LLM-assisted Cyber Threat Intelligence (CTI)** generation for **5G O-RAN security**. The framework combines machine learning-based threat detection with a locally deployed Large Language Model (LLM) to generate contextualized CTI alerts and incident reports.

This project was developed as part of the **PhD Coding Exercise: LLM-Assisted Cyber Threat Intelligence for 5G O-RAN Security**.

---

## Features

- Data preprocessing for the NetsLab-5GORAN-IDD dataset
- Multi-class threat detection using machine learning
- Performance evaluation using standard classification metrics
- Structured CTI alert generation (JSON)
- LLM-based CTI enrichment using **Qwen2.5:0.5B** through **Ollama**
- Automatic incident report generation
- SHAP-based explainability support (optional)

---


## Requirements

- Python 3.11 or later
- Ollama
- Qwen2.5:0.5B model

Install the required Python packages:

---

## LLM Setup

Install **Ollama** from:

https://ollama.com

Pull the required model:

```bash
ollama pull qwen2.5:0.5b
```

Start the Ollama server:

```bash
ollama serve
```

---

## Dataset

Download the **NetsLab-5GORAN-IDD** dataset and place it in the `Data/` directory.

> **Note:** The dataset is not included in this repository due to its size and distribution restrictions.

---

## Running the Framework

After training the model and configuring Ollama, execute:

```bash
cd "Part 2 CTI Alerts" 
python run_pipeline.py
```

The framework will:

1. Load the trained XGBoost model.
2. Predict the attack class for selected network events.
3. Generate structured CTI alerts.
4. Enrich the alerts using the local LLM.
5. Evaluate the generated CTI assessments.
6. Generate sample incident reports.

---

## Outputs

The framework produces:

- Trained machine learning models
- Model evaluation metrics
- Confusion matrices
- Structured CTI alerts (JSON)
- LLM-enriched CTI assessments
- Sample incident reports (Markdown)

---

## Machine Learning Models Evaluated

- XGBoost ✅ (Selected model)
- Random Forest
- LightGBM
- CNN (1D)
- Multi-Layer Perceptron (MLP)

Among the evaluated models, **XGBoost** achieved the highest performance and was selected for CTI alert generation.

---

## LLM Configuration

- **Model:** Qwen2.5:0.5B
- **Deployment:** Ollama (Local)
- **Inference:** Offline
- **API Key:** Not required

---
This repository is intended solely for academic and research purposes as part of the PhD coding exercise.

---

## Author

A.U. Taneesha Iyenshi
