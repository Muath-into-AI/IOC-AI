# Contributing

Thanks for your interest in ioc-enrich! Issues and pull requests are welcome.

## Setup

```bash
git clone https://github.com/Muath-into-AI/IOC-AI.git
cd IOC-AI
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .
ruff format --check .   # or `ruff format .` to fix
pytest
```

CI runs the same checks on Python 3.10, 3.11 and 3.12.

## Guidelines

- Keep the tool **defensive**: lookups and triage only. Features that scan, probe or
  attack systems won't be accepted.
- **No real API calls in tests.** Mock HTTP with `respx`. Never commit API keys.
- Add type hints and docstrings to public functions.
- Keep commits small and focused, with clear messages.
- Update `CHANGELOG.md` under "Unreleased".

## Adding a source

1. Create `src/ioc_enrich/sources/<name>.py` with a subclass of `Source`
   (`name`, `env_key`, `supported_types`, `rate_limit_per_minute`, `query()`).
2. Use `self.request(...)` for HTTP so rate limiting, timeouts and retries apply.
3. Return a `SourceResult` with a small, documented `data` dict.
4. Register it in `ALL_SOURCES` in `sources/__init__.py`.
5. Add a scorer in `scoring.py`, document the weighting in the README, and add tests.
