# Changelog

## Unreleased

### Fixed

- Deep Search admission now reserves capacity after validation without an intervening await.
- Searches no longer silently hide unavailable regions; partial results identify searched and skipped regions.
- Completed search states are published only after final coverage and scan metadata are available.
- Literal underscores and percent signs in path searches are preserved.
- Ingest errors and recovery thresholds are tracked per region and operation.
- Expired unresolved IP ownership records are retried.
- Retention cleanup recovers from errors instead of permanently stopping.
- Live-table fallback polling and stream reconnection resynchronize missed rows.
- Custom-window facets use the actual selected time window.
- Background ingest tasks are cancelled and awaited on application shutdown.

### Added

- Regression coverage for backend recovery, search correctness, lifecycle, and frontend stream behavior.
- Hash-locked development/test/audit dependencies and a synthetic hardened-container CI smoke test.
- Deployment, reverse-proxy, backup/recovery, and contribution guidance.
- Finalized MIT copyright notice and application license included in the container image.

### Changed

- Docker Compose forwards documented tuning settings and optional environment credentials.
- Profile/SSO documentation covers shared credentials paths, token cache location, and non-root permissions.
- Python 3.12 is the supported and tested runtime; frontend tests require Node 22 or newer.
