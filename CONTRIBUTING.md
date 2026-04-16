# Contributing

This repository is **proprietary**. Suggestions and collaboration are still
welcome, but access and redistribution follow [LICENSE](LICENSE). Before
large or invasive work, **contact the maintainer** so expectations and rights
are aligned.

## Ways to contribute

- **Rule improvements:** Better Suricata/Sigma/YARA signatures, reduced
  false positives, additional detection logic
- **New CVE profiles:** Additional CVE honeypot templates for `cve_templates.py`
- **ML/detection improvements:** Better anomaly detection algorithms,
  clustering approaches, or feature engineering
- **Documentation:** Corrections, additional setup guides, translations
- **Bug reports:** Open an issue with reproduction steps (for sensitive
  topics, follow [SECURITY.md](SECURITY.md) instead of a public issue)

## License grant for merged contributions

If you open a pull request and it is **merged**, you grant **Daniel Ferdinand
Hensen (Leviticus-Triage)** a perpetual, worldwide, royalty-free, irrevocable
license to use, modify, distribute, and sublicense your contribution **as part
of this project** under the same terms as the rest of the repository, without
any additional compensation. You confirm you have the right to grant this
license.

## Process

1. Ensure you have **repository access** (this project is not public-by-default
   distribution; forks and clones should respect [LICENSE](LICENSE)).
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
