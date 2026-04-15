# RedSOC 🔴

An adversarial evaluation framework for LLM-integrated Security Operations Centers.

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
