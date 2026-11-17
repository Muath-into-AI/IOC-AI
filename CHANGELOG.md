# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-17

### Added

- `ioc-enrich` CLI: IOCs from arguments, `-f FILE` or stdin.
- IOC type detection: MD5, SHA1, SHA256, IPv4, IPv6, domain, URL, email.
- Refanging of defanged input (`hxxp`, `[.]`, `(.)`, `[dot]`, `[@]`, `[:]//`).
- Sources: VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, AlienVault OTX; each skipped
  when its API key is missing.
- Documented 0–100 risk score with reasons and levels.
- Output as coloured table, JSON, CSV and Markdown report.
- HTTP timeout, per-source rate limiting, retry with exponential backoff.
- Optional SQLite cache with TTL.
- Config from environment variables or `.env`.
- Tests with mocked HTTP and GitHub Actions CI on Python 3.10–3.12.

[Unreleased]: https://github.com/Muath-into-AI/IOC-AI/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Muath-into-AI/IOC-AI/releases/tag/v0.1.0
