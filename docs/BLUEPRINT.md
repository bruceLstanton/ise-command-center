# Project blueprint

Reviewed against source: 2026-11-01. Handoff: [Status](STATUS.md). Operations: [Handbook](HANDBOOK.md).

## Purpose and environments

One interface for geographically separated Cisco ISE deployments, starting with inventory, health, and certificates and eventually extending to controlled configuration.

User decisions: Python 3.12 is the common target; RHEL 10.2 is the development environment; RHEL 9 with Python 3.12 is production. Windows remains a local development environment. Linux deployment has been discussed but not validated here.

## Architecture and source map

Browser → Flask routes/Jinja → SQLAlchemy inventory/audit database.
Flask routes → Fernet credential decryption → Requests client → ISE PAN01/PAN02 APIs.

| Source | Responsibility |
| --- | --- |
| app.py | Flask/Gunicorn app entry; direct execution enables a debug server |
| portal/__init__.py | App factory, environment settings, table creation/additive schema changes, demo seed |
| portal/models.py | Cluster connection settings, cached health/node/certificate data, audit events |
| portal/security.py | Fernet encryption/decryption with external runtime master key |
| portal/ise_client.py | API requests, PAN selection/fallback, payload normalization, certificates, ERS helpers |
| portal/routes.py | UI actions, validation, persistence, JSON card refresh, audits |
| portal/templates/ and portal/static/ | UI and styling |
| tests/test_app.py | Flask and mocked API regression tests |

## Implemented scope

- Add/edit/remove local cluster records with PAN01 and optional PAN02. Removal affects portal inventory, not the ISE deployment.
- Refresh version/patch, node health/details, backup summary, replication and certificate expiration; cache the results. Successful checks are healthy only if all reported nodes are connected. Failed checks mark the cluster offline.
- Prefer the last known primary PAN, with alternate PAN attempts on request exceptions. Selected certificate reads also fall back on configured HTTP error statuses; not every HTTP error triggers failover.
- Certificate inventory filters for issuer containing `ltma` and usage containing `admin`; trusted certificates use `trustedFor`. Empty results do not establish that ISE has no certificates.
- Trusted and system PEM certificate imports, including a private key for system imports. Forms use action-specific credentials. These are real ISE write operations for real clusters.
- Saved inventory passwords encrypted with Fernet; key supplied externally. Audit records currently default to actor `local-admin`.
- Demo seed only when cluster table is empty; demo shortcuts apply to clusters without saved encrypted credentials. Demo mode alone does not prevent real ISE calls.
- Network-device ERS read/write client methods exist without UI. Licensing helper/field exists, but health does not fetch licensing data.

## Routes

| Route | Purpose |
| --- | --- |
| GET / | Dashboard |
| GET /clusters/<id> | Cached details |
| GET, POST /clusters/new | Add inventory |
| GET, POST /clusters/<id>/edit | Edit connection |
| POST /clusters/<id>/check | Live refresh and persistence; AJAX JSON supported |
| POST /clusters/<id>/delete | Remove local inventory |
| GET /clusters/<id>/certificates | Live filtered inventory |
| GET, POST /clusters/<id>/certificates/import | Trusted certificate import |
| GET, POST /clusters/<id>/certificates/import-system | System certificate/key import |
| GET /audit | Latest 250 audit records |

API paths and payloads are authoritative in portal/ise_client.py: deployment, patch, backup/restore and certificate OpenAPI; ERS version and network-device APIs. Tests include ISE 3.3 payload cases, not universal version compatibility. Connect/read timeouts are 5/25 seconds per attempt; multi-call operations can take longer.

## Intended production state and gaps

Proposed deployment: HTTPS Nginx or Apache → Gunicorn → Flask, managed by systemd as a dedicated account. Service/proxy files are not currently delivered.

Before production exposure: authentication/roles, CSRF protection, authenticated audit identity, secure cookie settings, upload limits, required production secrets, explicit migrations replacing startup schema mutation, persistent data permissions, backup/recovery, CA trust, SELinux/firewalld, logging and timeout design.

SQLite is current. PostgreSQL is a future concurrency/operations choice, not required merely to run on Linux. Background jobs, drift comparison, bulk approvals, vault integration, and broad configuration management remain future scope.

Preserve the master key when migrating the database. Source checkout does not recover inventory/secrets. Follow [maintenance instructions](../AGENTS.md) when changing the design.
