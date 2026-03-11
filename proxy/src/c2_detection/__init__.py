"""
C2 & Covert Channel Detection Engine

Analyzes Suricata flow, DNS, and alert data from Elasticsearch to detect:
- Beaconing patterns (regular callback intervals)
- DNS tunneling (entropy, query frequency, record type anomalies)
- Protocol anomalies (ICMP tunneling, unusual packet sizes)
- Encrypted channel indicators (JA3 fingerprints, certificate anomalies)

Results are pushed to a dedicated ES index for dashboard visualization.
"""
