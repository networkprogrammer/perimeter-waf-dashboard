# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting
("Security" tab, "Report a vulnerability") on this repository. Include the affected version or commit, the
configuration involved, and synthetic steps to reproduce. Do not attach credentials or unsanitized WAF logs.
There is no guaranteed response time. Repository maintainers must enable private vulnerability reporting
before publication; this local export cannot configure that GitHub setting.

## Supported versions

The initial public release is being prepared. Until releases are tagged, report against the latest source snapshot
and include its commit or archive version. No long-term support or security backport policy is promised.

## Scope and deployment expectations

- The dashboard has no user accounts. Anyone who can reach it can read the WAF data it holds and start Deep
  Searches (which cost Athena money). Deploy it on loopback, a private network, or behind an authenticating proxy.
- `WAF_BASIC_AUTH` is a convenience gate for small setups; use it only over HTTPS.
- The AWS role it runs as should have the read-only, least-privilege permissions in `docs/iam.md`.

Reports about information that the dashboard intentionally shows to its users (for example the AWS caller identity on
the status strip, or request details in the row drawer) are out of scope unless they are reachable by someone who
should not have access.
