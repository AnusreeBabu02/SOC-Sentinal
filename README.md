# 🛡️ SOC Sentinel — Automated Logfile Anomaly, Threat & Attack-Chain Classifier

A lightweight, Wazuh-style SIEM dashboard that fuses four detection layers into one
pipeline:

1. **Unsupervised ML** — TF-IDF log-message embeddings + Isolation Forest anomaly scoring
2. **Sigma-style rules** mapped to **MITRE ATT&CK** tactics/techniques, plus IOC extraction
3. **Offline CVE mapping** — exploit-attempt signatures and vulnerable-version banners
4. **Temporal attack-chain correlation** — individual detections are stitched into
   scored, multi-stage incidents that follow the ATT&CK kill chain

Instead of a flat list of alerts, SOC Sentinel tells the analyst *which alerts belong to
the same intrusion, how far it progressed, and how urgent it is.*

## Features

### Ingestion & parsing
- Parses Windows/Sysmon text exports, Linux `auth.log`/syslog, Apache/Nginx access logs,
  SSH logs, and JSON lines into ECS-like structured fields.
- Generic fallback parser recovers timestamps, hosts and IPs from unknown formats.
- Timestamps from all formats are normalized so mixed-source logs sort correctly.

### Detection
- **Anomaly detection:** unsupervised (no labeled data) TF-IDF + Isolation Forest.
- **MITRE ATT&CK rules:** 15 built-in Sigma-style rules across 10 tactics (Initial Access,
  Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access,
  Discovery, Lateral Movement, Command & Control, Impact).
- **IOC extraction:** IP addresses and suspicious command-line indicators.
- **CVE mapping (fully offline):** 20 high-impact CVEs (Log4Shell, Shellshock, Spring4Shell,
  PrintNightmare, EternalBlue, regreSSHion, ProxyShell, …) detected three ways:
  - `exploit_attempt` — payload signature seen in traffic (also matched URL-decoded)
  - `vulnerable_version` — banner in a known-vulnerable range (Apache, OpenSSH, OpenSSL, Log4j)
  - `mentioned` — literal CVE ID in the log
  Each hit carries a CVSS score, severity, and an NVD link.

### Attack-chain correlation
- Detections (MITRE hits + CVE exploit attempts) that share a **host or IP** within a
  configurable time window are linked into one incident (union-find), so a chain can span
  several hosts via a shared attacker IP.
- Each incident is ordered in time, compared to the ATT&CK kill-chain order, and matched
  against known **playbooks** (e.g. *Brute force → account takeover → privilege escalation*,
  *Intrusion → ransomware impact*).
- Incidents are scored 0–100 and levelled critical / high / medium / low:

  ```
  score = 10·distinct_tactics + 2·rule_weight_sum + 15·playbooks_matched
          + 10·kill_chain_progression + max_cvss + 5·min(anomalies, 3)
  ```

### Dashboard
- Wazuh-style dark theme with KPI cards (logs, anomalies, MITRE hits, compromised hosts, CVEs).
- Tactic donut chart, technique leaderboard, and anomaly-score timeline.
- CVE vulnerability table with CVSS, affected hosts and NVD links.
- Incident table with an interactive per-incident kill-chain timeline.
- Searchable/filterable event explorer (text, technique, host, severity, CVE) with
  color-coded severity badges and an expandable JSON detail viewer.
- One-click demo dataset with embedded attack scenarios: SSH brute force, privilege
  escalation, PowerShell encoded execution, credential dumping, web shell + SQLi, port
  scan, C2 beacon, lateral movement, ransomware indicators.
- Export enriched results as CSV or JSON; one-click MITRE/CVE/incident summary.

## Pipeline

```
Parser → TF-IDF + Isolation Forest → MITRE/IOC Enricher → CVE Mapper → Chain Correlator → Dashboard
```

Event severity: **critical** = rule/CVE hit *and* ML anomaly · **medium** = rule/CVE hit only ·
**suspicious** = ML anomaly only · **informational** = neither.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open http://localhost:8501, click **Load Demo Dataset** in the sidebar, and
hit **Run Analysis Pipeline** — or upload your own `.log` / `.txt` / `.json` files.

## Run with Docker

```bash
docker build -t soc-dashboard .
docker run -p 8501:8501 soc-dashboard
```

Open http://localhost:8501.

## Deploy to Render / Railway / any container host

The Dockerfile respects the `$PORT` environment variable injected by most PaaS
providers (Render, Railway, Heroku-style buildpacks), so no config changes are
needed — just point the platform at this repo/Dockerfile and deploy.

## Project structure

```
soc-dashboard/
├── app.py                  # Streamlit dashboard (UI + orchestration)
├── core/
│   ├── parser.py            # Log parser — normalizes raw logs to ECS-like fields
│   ├── ml_engine.py         # TF-IDF + Isolation Forest anomaly detector
│   ├── mitre_rules.py       # Sigma-style rule set mapped to MITRE ATT&CK
│   ├── enricher.py          # MITRE & IOC enrichment engine
│   ├── cve_mapper.py        # Offline CVE signature + version-banner mapper
│   ├── correlator.py        # Temporal attack-chain correlator & incident scorer
│   └── demo_data.py         # Synthetic multi-format demo log generator
├── assets/
│   └── style.css            # Wazuh-inspired dark theme
├── requirements.txt
├── Dockerfile
└── .dockerignore
```

## Tuning

- **Contamination Rate** (0.01–0.20): expected proportion of anomalous events — raise it
  for noisier/dirtier log sources, lower it for tight production baselines.
- **Strict Rule Sensitivity**: ON makes MITRE rule matching case-sensitive (fewer,
  higher-confidence hits); OFF is case-insensitive/broader matching.
- **Correlation window** (5–180 min): max gap between detections on the same host/IP for
  them to be linked into one incident.
- **Min. distinct tactics per chain** (1–5): only report incidents spanning at least this
  many ATT&CK tactics.

## Extending

- **Rules:** append a dict to `RULES` in `core/mitre_rules.py` with `rule_id`, `name`,
  `tactic`, `technique_id`, `technique_name`, `pattern` (regex), `severity_weight`.
- **CVEs:** add an entry to `CVE_INFO`, a regex to `SIGNATURES`, and/or a product banner
  to `VERSION_RULES` in `core/cve_mapper.py`.
- **Playbooks:** add an ordered list of tactic sets to `PLAYBOOKS` in `core/correlator.py`.
- **Log formats:** add a parser branch inside `parse_line()` in `core/parser.py`.

## Limitations

- Version-banner CVE findings may be false positives where distro vendors backport
  patches — verify before acting.
- The CVE table is a curated offline subset, not the full NVD feed.
- Isolation Forest scores message *text* novelty; it does not model timing or volume.
