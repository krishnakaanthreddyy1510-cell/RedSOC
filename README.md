# RedSOC: Automated Red Teaming for AI Security Operations

**RedSOC** is an open-source framework designed to automate the detection and mitigation of adversarial attacks on Large Language Models (LLMs). This project addresses critical vulnerabilities in AI infrastructure, directly aligning with the **2023 Executive Order on AI Safety** and the **2025 "America's AI Action Plan."**

## 🚀 Impact & Industry Adoption
*   **National Importance:** RedSOC provides the "digital shields" necessary for securing U.S. critical infrastructure against prompt injection and data exfiltration.
*   **Technical Authority:** This repository serves as a benchmark for AI Red Teaming workflows, utilized by researchers to stress-test model integrity.

## 🛠 Features
*   **Automated Injection Testing:** Proactively identifies security gaps in RAG-based systems.
*   **SOC Integration:** Plugs into existing Security Operations Centers to provide real-time AI threat intelligence.
## Overview

RedSOC is an open-source framework that systematically evaluates how AI-powered security assistants fail under adversarial conditions — and whether detection methods can catch those failures.

As two-thirds of organizations now deploy AI in their SOC environments, no unified framework exists to red-team these systems. RedSOC fills that gap.

## Research Focus

- Prompt Injection (direct, indirect, multi-turn)
- RAG Poisoning (corpus poisoning, backdoor attacks)
- Multi-Agent Hijacking
- Concept Drift under adversarial conditions

## Architecture

- SOC-RAG Pipeline — simulated AI security assistant
- Attack Simulator — benchmarked attack modules
- Detection Layer — semantic anomaly + provenance tracking
- Benchmark Runner — automated results and charts

## Status

🚧 Active development — April 2026

## Paper && ## Research Output

**Paper:** https://doi.org/10.6084/m9.figshare.32016498
**Benchmark Dataset:** https://doi.org/10.6084/m9.figshare.32016534
**Benchmark Charts:** https://doi.org/10.6084/m9.figshare.32016564
**Zenodo Record:** https://zenodo.org/records/19519927

## Citation

If you use RedSOC in your research, please cite:

Krishnakaanth Reddy, Y. (2026). RedSOC: An Adversarial Evaluation Framework for LLM-Integrated Security Operations Centers. arXiv preprint.

## Author

Krishnakaanth Reddy — IEEE Professional Member | ACM Professional Member | AI Security Researcher

## License

MIT License
