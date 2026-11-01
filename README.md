# ISE Command Center

A Flask portal for managing geographically separated Cisco ISE deployments.

**Returning after a break? Start with [Quick start](docs/QUICK_START.md), then [Current status](docs/STATUS.md).**

- [Blueprint](docs/BLUEPRINT.md): architecture, scope, source map, and intended end state.
- [Handbook](docs/HANDBOOK.md): configuration, operations, troubleshooting, and development.
- [Quick start](docs/QUICK_START.md): resume safely and verify the baseline.
- [Current status](docs/STATUS.md): last verified state, open issues, and next task.
- [Contributor instructions](AGENTS.md): documentation maintenance requirements.

Capabilities: cluster inventory, health, PAN fallback, filtered certificate inventory, certificate imports, encrypted saved passwords, and audit history. Network-device ERS helpers exist without a management UI.

Target: Python 3.12, RHEL 10.2 development, RHEL 9 production. Windows is also used for local development. Production access controls and deployment configuration remain unfinished.

[GitHub repository](https://github.com/bruceLstanton/ise-command-center)
