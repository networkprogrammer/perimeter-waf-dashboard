# Contributing

Keep contributions focused and preserve the self-hosted, no-build, no-runtime-LLM architecture.
Read [README.md](README.md), [docs/architecture.md](docs/architecture.md), and [AGENTS.md](AGENTS.md) first.

## Development checks

Use Python 3.12 and Node 22 or newer:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --only-binary :all: -r requirements-dev.txt
python -m unittest tests.test_backend
node --experimental-vm-modules --test tests/test_frontend.mjs
pip-audit -r requirements.txt --require-hashes --disable-pip
```

Backend tests stub AWS and external ownership lookups. Frontend regressions use Node's built-in test runner;
no npm dependencies or application build step are required. CI also builds and starts the hardened container
with synthetic data. Add a regression test that fails before fixing a behavior defect.

## Pull requests

- Explain the behavior change, its motivation, and the validation performed.
- Use placeholders and synthetic fixtures only. Never include real logs, account identifiers, hostnames,
  certificates, credentials, or screenshots from an unsanitized deployment.
- Keep SQL parameterized, AWS operations restricted to the documented query/metadata/STS behavior, and UI
  rendering limited to safe DOM APIs. Preserve the current access-control and CSP checks.
- Update related documentation. Change dependency manifests and regenerate their hash locks together.
- Include a screenshot for visible UI changes, generated with demo mode and a separate disposable data directory.
- Contributions are provided under the project's [MIT license](LICENSE). Preserve third-party license notices.

## Support and security

Open a normal issue for bugs or feature requests with the configuration shape, version/commit, and synthetic
reproduction steps. Remove credentials and identifying log content. This project has no guaranteed support SLA.
For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
