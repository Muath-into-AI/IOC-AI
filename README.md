# ioc-enrich

[![CI](https://github.com/Muath-into-AI/IOC-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Muath-into-AI/IOC-AI/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small command-line tool that takes **indicators of compromise (IOCs)**, looks them up
in **free threat-intel sources**, and gives you a **0–100 risk score with reasons**.

It is **strictly defensive**: it only looks indicators up and triages them. It never
scans, probes or exploits any system, and it sends IOCs only to the sources you configure.

**Who it's for:** SOC analysts, incident responders, threat-intel and security researchers
who want a fast first look at a hash, IP, domain, URL or email address.

## Features

- **Input:** one or more IOCs as arguments, a file (`-f iocs.txt`), or stdin.
- **Auto-detects the IOC type:** MD5, SHA1, SHA256, IPv4, IPv6, domain, URL, email.
- **Refangs defanged input:** `hxxp://`, `[.]`, `(.)`, `[dot]`, `[@]`, `[:]//` …
- **Sources** (each one is skipped if its API key is missing):

  | Source | Env var | IOC types |
  |---|---|---|
  | [VirusTotal](https://www.virustotal.com/) | `VT_API_KEY` | hashes, IPs, domains, URLs |
  | [AbuseIPDB](https://www.abuseipdb.com/) | `ABUSEIPDB_API_KEY` | IPs |
  | [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | `ABUSECH_AUTH_KEY` | URLs, domains, IPs, MD5/SHA256 payloads |
  | [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) | `ABUSECH_AUTH_KEY` | hashes |
  | [AlienVault OTX](https://otx.alienvault.com/) | `OTX_API_KEY` | hashes, IPs, domains, URLs |

- **Risk score 0–100** per IOC, with a short list of reasons.
- **Output:** coloured table (default), `--json`, `--csv`, `--md` (Markdown report).
- **Safe by default:** HTTP timeout, per-source rate limiting, retry with exponential
  backoff (honours `Retry-After`), and an optional local **SQLite cache** with a TTL.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/Muath-into-AI/IOC-AI.git
cd IOC-AI
pip install .            # or: pip install ".[dev]" for tests and linting
ioc-enrich --version
```

## Configuration

API keys come from environment variables or a `.env` file in the current directory
(or the file given with `--env-file`). Copy the template and fill in the keys you have:

```bash
cp .env.example .env
```

```ini
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
ABUSECH_AUTH_KEY=...
OTX_API_KEY=...
```

All keys are optional; sources without a key are skipped. `.env` is git-ignored —
**never commit keys.**

| Setting | Default | |
|---|---|---|
| `IOC_ENRICH_CACHE` | `~/.cache/ioc-enrich/cache.sqlite` | cache file |
| `IOC_ENRICH_CACHE_TTL` | `86400` (24 h) | cache TTL in seconds |

## Usage

```bash
# single IOC (defanged is fine)
ioc-enrich 'hxxp://example[.]com'

# several IOCs
ioc-enrich 44d88612fea8a8f36de82e1278abb02f 8.8.8.8

# from a file (one per line, '#' comments allowed) or stdin
ioc-enrich -f iocs.txt
cat iocs.txt | ioc-enrich --json

# output formats
ioc-enrich -f iocs.txt --csv -o results.csv
ioc-enrich -f iocs.txt --md  -o report.md

# only some sources, no cache, shorter timeout
ioc-enrich 8.8.8.8 --sources virustotal,abuseipdb --no-cache --timeout 10
```

Run `ioc-enrich --help` for all options.

### Sample output

The EICAR test-file MD5, Google's public DNS, and a defanged `example.com` URL:

```text
$ ioc-enrich 44d88612fea8a8f36de82e1278abb02f 8.8.8.8 'hxxp://example[.]com'
                                                   ioc-enrich results
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ IOC                          ┃ Type ┃ Score ┃ Level    ┃ Sources                      ┃ Reasons                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 44d88612fea8a8f36de82e1278ab │ md5  │    95 │ critical │ virustotal: 63/72 engines    │ - VirusTotal: 63 engines     │
│ b02f                         │      │       │          │ malicious                    │ flag as malicious            │
│                              │      │       │          │ urlhaus: not listed          │ - MalwareBazaar: known       │
│                              │      │       │          │ malwarebazaar: known sample: │ malware sample               │
│                              │      │       │          │ EICAR-Test-File (com)        │ (EICAR-Test-File)            │
│                              │      │       │          │ otx: 2 pulses                │ - OTX: referenced in 2       │
│                              │      │       │          │                              │ pulses                       │
├──────────────────────────────┼──────┼───────┼──────────┼──────────────────────────────┼──────────────────────────────┤
│ 8.8.8.8                      │ ipv4 │     0 │ none     │ virustotal: 0/92 engines     │ - AbuseIPDB: IP is           │
│                              │      │       │          │ malicious                    │ whitelisted                  │
│                              │      │       │          │ abuseipdb: confidence 0%, 41 │                              │
│                              │      │       │          │ reports                      │                              │
│                              │      │       │          │ urlhaus: not listed          │                              │
│                              │      │       │          │ otx: 0 pulses                │                              │
├──────────────────────────────┼──────┼───────┼──────────┼──────────────────────────────┼──────────────────────────────┤
│ http://example.com           │ url  │     0 │ none     │ virustotal: 0/93 engines     │ - no source reported         │
│                              │      │       │          │ malicious                    │ malicious activity           │
│                              │      │       │          │ urlhaus: not listed          │                              │
│                              │      │       │          │ otx: 0 pulses                │                              │
└──────────────────────────────┴──────┴───────┴──────────┴──────────────────────────────┴──────────────────────────────┘
```

> The numbers above are illustrative; live results change as the sources update.

`--json` (truncated):

```json
{
  "ioc": "44d88612fea8a8f36de82e1278abb02f",
  "original": "44d88612fea8a8f36de82e1278abb02f",
  "type": "md5",
  "score": 95,
  "level": "critical",
  "reasons": [
    "VirusTotal: 63 engines flag as malicious",
    "MalwareBazaar: known malware sample (EICAR-Test-File)",
    "OTX: referenced in 2 pulses"
  ],
  "sources": [
    {
      "source": "virustotal",
      "status": "found",
      "data": {"malicious": 63, "suspicious": 0, "harmless": 0, "undetected": 9, "reputation": null},
      "summary": "63/72 engines malicious",
      "error": null
    }
  ]
}
```

Each source result has a `status`: `found`, `not_found`, `skipped` (no API key),
`unsupported` (source can't look up this IOC type) or `error`.

## How the risk score is calculated

Each source adds points; the total is clamped to 0–100. The weighting is deliberately
simple so it is easy to reason about (see `src/ioc_enrich/scoring.py`).

| Source | Signal | Points |
|---|---|---:|
| VirusTotal | ≥ 10 engines malicious | 50 |
| | 3–9 engines malicious | 35 |
| | 1–2 engines malicious | 15 |
| | any engine "suspicious" (VirusTotal total capped at 50) | +5 |
| AbuseIPDB | abuse confidence score × 0.4 | 0–40 |
| | IP is on AbuseIPDB's whitelist | −10 |
| URLhaus | IOC is listed | 30 |
| | listed URL still online / host has online URLs | +10 |
| MalwareBazaar | hash is a known sample | 40 |
| OTX | ≥ 10 pulses | 20 |
| | 3–9 pulses | 12 |
| | 1–2 pulses | 5 |

| Score | Level |
|---|---|
| 0 | none |
| 1–29 | low |
| 30–59 | medium |
| 60–79 | high |
| 80–100 | critical |
| no source returned data | unknown |

A score is a **triage aid, not a verdict**. Popular infrastructure (public DNS, CDNs)
often shows up in OTX pulses or abuse reports; always read the reasons and the raw data.

## Ethical use

- This tool is for **defensive triage only**: investigating alerts, incidents and
  threat intel. Do not use it to target, scan or attack systems.
- Respect each source's **terms of service and rate limits** (VirusTotal's free API, for
  example, is for non-commercial use and allows 4 requests/minute).
- Be careful with **sensitive IOCs**: anything you look up is sent to the configured
  third-party services. Don't submit confidential data (internal hostnames, customer
  email addresses, private URLs) unless your policies allow it. Use `--sources` to limit
  where an IOC goes.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest
```

Tests mock all HTTP with [`respx`](https://lundberg.github.io/respx/); they never call the
real APIs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- YARA rule matching for files
- Sigma rule suggestions based on enrichment results
- STIX 2.1 export
- MISP integration (lookup and push)

## Built with AI assistance

This project was built with the help of an AI coding assistant (Claude Code).
I designed the tool, and reviewed and tested the code.

## License

[MIT](LICENSE)
