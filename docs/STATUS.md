# Current project status

Last handoff: 2026-11-01. Start here, then [Quick start](QUICK_START.md).

## Current state and decisions

- Flask MVP implements inventory, cached health/details, PAN fallback, filtered certificate inventory, certificate imports and audits. [Blueprint](BLUEPRINT.md) distinguishes shipped scope from future work.
- Earlier session pushed initial commit 79f04a9 to main at [GitHub](https://github.com/bruceLstanton/ise-command-center).
- User confirmed RHEL 10.2 development and RHEL 9 production with Python 3.12 installed on production. Python 3.12 is the common target.
- Existing Windows virtual environment metadata reports Python 3.14.2; it has not been rebuilt for that target.
- No RHEL deployment or live ISE integration was validated in this session.

## Latest work

Created blueprint, handbook, quick start and this handoff. Replaced outdated README with a documentation entry point. Added AGENTS instructions requiring documentation changes with meaningful project changes and an updated end-of-session handoff.

Guides preserve master keys, isolate demo data, explain Windows startup, and separate implemented behavior from production plans.

## Validation

2026-11-01: `.venv/Scripts/python.exe -m pytest -q` in existing Windows environment: **49 passed**, one pytest cache-write warning. This is mocked/in-memory validation, not Python 3.12, RHEL or live ISE verification.

Documentation links/source references checked locally. Documentation changes are included in the project return-kit commit. No new push performed; the commit remains local until pushed.

## Open issues

- Earlier chat ended at ISE HTTP 401 with suspected username mismatch; current resolution is unknown. Confirm rather than assuming it remains broken.
- Existing master-key recovery location is not established in these guides. Obtain it from the owner's secret storage; never regenerate it for an existing database.
- Production authentication/roles, CSRF, audit identity, upload limits, mandatory secrets, explicit migrations, service/proxy setup and backup procedures remain unfinished.
- Choose deployment layout, proxy, certificate source, database strategy and secret delivery before building production deployment files.
- Documentation freshness is a contributor workflow through AGENTS, not automatic generation or CI enforcement.

## Next concrete task

Validate a fresh **Python 3.12 environment on RHEL 10.2**: install requirements, run tests, start an isolated demo using Quick start, and record commands/results here. Preserve existing Windows environment, real database and master key.

Then verify read-only ISE connectivity with trusted CA configuration from that server. Resolve authentication/TLS issues before certificate writes. Use evidence to prepare RHEL 9 deployment and prioritize production access controls.

## Updating this handoff

Replace obsolete current-state and next-step entries rather than growing a diary. Include date, changes, actual validation/environment, open issues, next action and accurate commit/push state. Never include secrets or sensitive payloads. Git holds historical changes.
