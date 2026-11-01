# Repository instructions

Before work, read docs/STATUS.md and the relevant portions of docs/BLUEPRINT.md, docs/HANDBOOK.md, and docs/QUICK_START.md. Inspect current source and Git state; a dated handoff does not establish today's runtime or connectivity.

## Documentation is part of completion

For every meaningful change, update affected documentation in the same change:

- Architecture, routes, data, integration behavior, scope, or deployment design: docs/BLUEPRINT.md.
- Configuration, dependencies, operations, troubleshooting, security, or testing: docs/HANDBOOK.md.
- Setup, startup, shutdown, recovery, or initial verification: docs/QUICK_START.md.
- End every session that changes the project by refreshing docs/STATUS.md with date, completed work, actual checks/environment, unresolved issues, and the next concrete action. Preserve relevant decisions; remove obsolete handoff details.
- Keep README links and capability summary accurate. Do not change verification dates for documents you did not review.

Distinguish planned, implemented, and verified behavior. Never claim RHEL or live ISE validation from mocked Windows tests. Record commit/push state accurately; do not push without applicable user authorization.

Never document or commit passwords, tokens, master keys, private keys, or sensitive diagnostic payloads. Keep instance/, .venv/, .env (and secret variants), work/, and outputs/ ignored. Preserve the existing master key when resuming an existing database. Demo mode is not an isolation boundary: credential-bearing clusters can still call real ISE. Use a separate demo database.

Run relevant existing tests for behavior changes. For documentation-only changes, check local links, commands, and source references. Do not perform real ISE writes merely to validate documentation. Inspect the diff before handoff.

These instructions guide agents in this repository. They do not automatically update documents for human or external edits; human contributors should follow the same checklist. No unattended documentation monitor is installed.
