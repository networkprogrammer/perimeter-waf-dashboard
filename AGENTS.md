# Instructions for AI coding agents

This repository is a self-hosted dashboard for AWS WAF logs in Amazon Security Lake. Read `README.md` first, then
`docs/architecture.md`. To rebuild the project from scratch or port it to a new data source, follow
`docs/ai-agent-rebuild.md`.

## Rules for working in this repo

1. **Never add identifying data**: no real account IDs, bucket names, hostnames, IPs, ARNs, internal URLs, company
   or person names. Use placeholders (`<ACCOUNT_ID>`, `example.com`, `198.18.0.0/15`, `192.0.2.0/24`).
2. **No secrets**: no keys, tokens, certificates or `.env` files in git.
3. **Read-only against AWS**: the only AWS calls are Athena queries (SELECT), Glue/Athena metadata reads and STS. Do not add mutating calls.
4. **Parameters only**: user text never goes into SQL strings. SQLite uses `?`; Athena uses `ExecutionParameters`, which
   Athena parses as SQL expressions, so every text value must go through `athena.sql_literal()` (single-quoted, quotes doubled).
   Keep the strict input validation in `main._validate_search` as a second layer.
5. **UI**: no `innerHTML`, no external requests (strict CSP), no build step.
6. **Tests**: `python -m unittest tests.test_backend` must pass with no AWS access.
7. **ASCII punctuation** in strings and comments: use a plain hyphen, not an em dash.
8. **Dependencies**: edit `requirements.in`, regenerate the hash-locked `requirements.txt` (README "Dependencies"), keep `pip-audit` clean.
9. **Access checks** use `scope["path"]`, never `request.url` (which is rebuilt from the untrusted `Host` header).

## Model guidance

- Use a **Sonnet-class model** for backend code, tests, packaging and refactors.
- Use an **Opus-class model** for UI and visual design work in `app/static/` (layout, hierarchy, typography, interaction design).
- Have a second model review security-sensitive changes (SQL construction, input validation, headers).
