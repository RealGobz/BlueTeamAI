# Triagent Research & Benchmark

> **Investigation Results: 10 Test Scenarios**  
> *Empirical evaluation of an autonomous, human-in-the-loop AI security analyst investigating simulated Windows attacks and administrative false positives.*

[![Live Webpage](https://img.shields.io/badge/Live-Research%20Site-blue.svg)](https://realgobz.github.io/Triagent-Research/)
[![Research Paper](https://img.shields.io/badge/Paper-PDF%20Download-brightgreen.svg)](https://realgobz.github.io/Triagent-Research/Triagent-Research-Paper.pdf)
[![Main Agent Repo](https://img.shields.io/badge/GitHub-Triagent%20Core-orange.svg)](https://github.com/RealGobz/Triagent)

---

## 🌐 Live Research Site
Visit the interactive research website at:  
👉 **[https://realgobz.github.io/Triagent-Research/](https://realgobz.github.io/Triagent-Research/)**

- **Read the Full Paper**: [`Triagent-Research-Paper.pdf`](https://realgobz.github.io/Triagent-Research/Triagent-Research-Paper.pdf)
- **Single Source of Truth**: [`manifest.json`](manifest.json) & [`metrics.json`](metrics.json)

---

## 📊 Benchmark Summary

| Metric | Attacks ($n=5$) | Benign ($n=5$) | Aggregate |
| :--- | :--- | :--- | :--- |
| **Accuracy / Resolution** | **70.0%** (3 Yes, 1 Partial = 0.5, 1 No) | **100.0%** (5 Cleared, 0 Escalated) | &mdash; |
| **Median Time to Verdict** | 57.0s | 50.0s | **52.0s** |
| **Average Tokens** | 448,026 | 230,782 | **339,404** |
| **Average Cost (USD)** | $0.1792 | $0.0923 | **$0.1358** |

---

## 📂 Repository Contents

```text
├── index.html                   # Interactive research webpage
├── styles.css                   # Custom responsive styling (Triagent brand theme)
├── manifest.json                # Structured dataset for all 10 scenario runs
├── metrics.json                 # Aggregate benchmark performance metrics
├── Triagent-Research-Paper.pdf  # Compiled 12-page research paper PDF
├── paper.html & paper.css       # Source files for PDF generation
├── build.py                     # Single-command site & PDF compiler
├── brand/                       # Vector SVGs and brand theme tokens
├── scripts/                     # Downloadable simulation scripts (.ps1)
└── videos/                      # Demonstration recordings (.mp4)
```

---

## 📄 License & Attribution
- Open-source detection rules provided by [SigmaHQ](https://github.com/SigmaHQ/sigma).
- Behavioral simulation paradigms inspired by [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
- Triagent is licensed under Apache License 2.0.

