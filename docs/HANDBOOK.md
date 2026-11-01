# Project handbook

Reviewed against source: 2026-11-01. [Quick start](QUICK_START.md) · [Blueprint](BLUEPRINT.md) · [Status](STATUS.md).

## Configuration and persistent state

| Variable | Current default/behavior | Operating rule |
| --- | --- | --- |
| FLASK_SECRET_KEY | dev-only-change-me | Persistent strong secret outside disposable demos |
| ISE_PORTAL_MASTER_KEY | Empty; Fernet key required for stored passwords | Restore the original key for an existing database |
| DATABASE_URL | sqlite:///ise_portal.db | Relative SQLite paths resolve under Flask's instance directory; default file is instance/ise_portal.db |
| ISE_PORTAL_DEMO | Off unless exactly 1 | Use a separate database; real credential-bearing clusters can still call ISE |

.env.example contains placeholders. The app reads process environment variables; python-dotenv is not a declared dependency. Do not assume .env loads automatically. Each shell or service needs its own environment configuration.

Git ignores instance/, .venv/, .env and variants (except the example), work/ and outputs/. Source checkout does not restore inventory, audit history or keys. Protect a consistent database backup and separately protected master key and service configuration. For a simple SQLite copy, stop the app first; otherwise use SQLite's backup mechanism. Restore to a separate path and verify before replacing working state.

Changing the Flask secret affects signed sessions. Changing the Fernet key prevents decrypting saved ISE passwords unless they are re-encrypted or re-entered. Do not regenerate it when restarting. Never put secret values in documentation or Git.

## Operations

Dashboard/details show cached values; refresh calls ISE and stores results. Real certificate inventory performs live reads. Editing with a blank password preserves the saved value. Remove deletes local inventory, not ISE.

Certificate imports are real ISE configuration changes and use action-specific credentials. System imports include a private key and its password. Existing validation is not an approval workflow or complete security boundary.

Production should use Gunicorn under systemd and an HTTPS reverse proxy. `app:app` is the existing entry point, but importing it initializes and changes the schema. Add explicit migrations before multiworker startup. Direct `python app.py` enables debug mode. No production deployment files or RHEL validation are currently provided.

## ISE connectivity

Configure PAN01/optional PAN02, a dedicated API account, TLS verification, and optionally a PEM CA bundle readable by the service account. Replace saved Windows CA paths on Linux. Verify DNS, routing, API services, roles and certificate chain from the actual host.

Requests uses Basic credentials and 5/25-second connect/read timeouts per attempt. Multiple calls/failover can accumulate. Optional endpoints can fail independently. Certificate inventory filters LTMA-issued Admin certificates; empty results can reflect the filter.

Use Python 3.12 and matching dependency pins on both RHEL systems. Test TLS on each host because native libraries and crypto policies differ. FIPS status is unknown; investigate if your deployment requires it.

## Troubleshooting

| Symptom | First checks |
| --- | --- |
| Terminate batch job prompt | Use Python module startup instead of Windows flask.cmd |
| ISE HTTP 401 | Actual configured username/password, lock/expiry, API access; earlier chat suspected username mismatch without a recorded successful resolution |
| HTTP 403 | API permissions/services and actual response |
| TLS error | Hostname, validity, chain, readable CA bundle, host crypto policy |
| InsecureRequestWarning | Verification disabled; configure CA trust. This warning alone does not explain a 401 |
| Cannot decrypt stored credential | Recover original key for the database; do not overwrite data or generate another key |
| Empty certificate view | LTMA/Admin filter, endpoint errors, node reachability and permissions |
| Missing demo samples | Seed occurs only for an empty cluster table; check database selection |
| Service differs from shell | User, environment, working directory, file permissions, SELinux and networking |
| Slow requests | Identify failing endpoint and accumulated calls/failover before adjusting timeout limits |

Audit page shows latest 250 records; current actor defaults to local-admin. It is not external log retention. Review diagnostic errors for sensitive infrastructure details before sharing.

## Development and verification

Direct dependencies are pinned in requirements.txt; transitive dependencies are not fully locked. Tests in tests/test_app.py cover navigation, inventory actions, imports, failover, ISE 3.3 payload parsing, backup interpretation, and certificate expiration using in-memory databases and mocked requests. They do not establish security, load, live integration or Linux compatibility.

Use Quick start test commands. Add sanitized payload regression cases for API parsing changes, inspect affected pages for UI changes, and validate deployment changes on the target OS. Do not perform real certificate writes merely to test documentation.

Inspect `git status --short` and `git diff` before handoff. A dubious-ownership error in the Windows sandbox requires checking account/ownership; do not disable ownership checks globally or trust all directories.

## Pause and maintenance routine

1. Update STATUS with date, concrete changes, actual validation/environment, open issues and next task.
2. Update affected blueprint, configuration, startup and troubleshooting sections with the same change.
3. Remove stale handoff details, preserving relevant decisions.
4. Inspect Git diff and record whether changes are local, committed or pushed.
5. Keep database recovery and secrets in approved storage outside Git.

[AGENTS.md](../AGENTS.md) requires this workflow for agent work. Manual/external edits still need review; no unattended updater is installed.
