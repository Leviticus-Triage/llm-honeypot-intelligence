# Contributing

Contributions are welcome. Here is how you can help:

## Ways to contribute

- **Rule improvements:** Better Suricata/Sigma/YARA signatures, reduced
  false positives, additional detection logic
- **New CVE profiles:** Additional CVE honeypot templates for `cve_templates.py`
- **ML/detection improvements:** Better anomaly detection algorithms,
  clustering approaches, or feature engineering
- **Documentation:** Corrections, additional setup guides, translations
- **Bug reports:** Open an issue with reproduction steps

## Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improved-c2-detection`)
3. Make your changes
4. Run linting: `ruff check proxy/src/`
5. Submit a pull request with a clear description of the changes

## Code style

- Python: Follow PEP 8, use type hints where practical
- YAML rules: Follow the respective standard (Sigma specification, Suricata rule format)
- Commit messages: Imperative mood, concise (`add DNS tunneling detection for DoH`)

## What not to submit

- Credentials, API keys, or internal infrastructure details
- Offensive tooling or exploit code
- Raw Elasticsearch data or PII
