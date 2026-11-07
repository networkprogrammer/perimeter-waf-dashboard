# Deployment and recovery

The dashboard is a rolling diagnostic cache, not a durable audit archive. Amazon Security Lake remains the
source of truth. Run one application process/worker per data volume; multiple ingest processes are unsupported.

## Exposure and reverse proxy

Keep the default loopback bind unless the deployment network and authentication are explicitly configured.
The shared basic-auth gate is optional and must be used only over HTTPS. Set `WAF_ALLOWED_HOSTS` to the browser's
host name and `FORWARDED_ALLOW_IPS` to the actual proxy address, not `*`. A proxy in another container cannot
reach the host's loopback-published port without appropriate networking.

Example nginx location inside an existing TLS-enabled server for `waf.example.com`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1h;
}
```

This example does not configure TLS certificates or authentication. Add those controls before exposing it.
Disabling buffering is necessary for server-sent events. The browser reloads the current table after reconnecting
and uses polling while disconnected; paused views remain paused. URL subpath hosting is unsupported because UI
and API URLs are rooted at `/`.

## Health and diagnosis

- `/healthz` is process liveness only; a healthy process can still lack AWS access.
- `/api/status` reports credential probes, `ingest_errors` by operation/region, and retention cleanup state in
  `prune.last_success_ms` / `prune.last_error`. Keep it protected like the rest of the API. Investigate recurring
  errors even when other regions continue working. Cleanup has no success timestamp until its first scheduled run.
- Deep Search may return successful rows from only some configured regions. Inspect `partial`, `searched_regions`,
  and `skipped_regions`; the UI labels such results instead of presenting them as complete.
- Container logs rotate by default. Retention removes old cached events/counts, not Athena result objects.
  Configure a lifecycle rule on the Athena results prefix separately.
- Deep Search's scan budget is process-local and applies to searches, not polling. It is not an AWS billing cap;
  use workgroup scan controls and billing alerts for independent protection.

## Upgrades

1. Read the release notes and record the version/commit currently deployed. Keep the previous image available.
2. Back up the data volume if preserving the current rolling cache matters.
3. Rebuild the selected release with `docker compose build`, then recreate with `docker compose up -d`.
4. Verify `/healthz`, protected `/api/status`, region access, advancing poll times, and fresh rows. Check container logs.

There is no general-purpose schema migration framework. Follow any release-specific migration instructions;
otherwise use a new empty volume if an incompatible schema change is announced. Do not run old and new versions
against the same volume concurrently. Rolling back an image does not roll back database changes.

## Backup and restore

SQLite uses WAL mode. Do not copy only the database file while the app is writing: recent transactions may still
be in the WAL. Use SQLite's online backup API, or stop the service and copy the complete `/data` volume with a
trusted backup tool. The actual Docker volume name depends on your Compose project; identify it before acting.

For restore, stop the service, restore into the intended data volume, and preserve ownership for uid/gid 10001.
Use a backup compatible with the deployed schema. Restart and verify poll progress and region state. Protect
backups as sensitive WAF logs; they can contain client IPs, request paths, query strings, and user agents.

If the cache is disposable, use a new empty volume rather than deleting the old one. First start backfills
`WAF_BACKFILL_HOURS` and incurs Athena scan costs again. Backfill defaults to 24 hours even though retention is
72 hours, so a new cache will not immediately contain the full retention window.

## Publication checklist

- Finalize release ownership/permission and retain the MIT and font license notices.
- Run backend/frontend tests, the dependency audit, and the container smoke check.
- Review the exact files and screenshots being published, plus Git history if the repository has one.
- Keep GitHub private vulnerability reporting enabled; [SECURITY.md](../SECURITY.md) directs users to that channel.
- Tag a tested release and update [CHANGELOG.md](../CHANGELOG.md).
