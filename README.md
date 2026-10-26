# ISE Command Center

A Flask foundation for managing multiple geographically separated Cisco ISE deployments from one audited portal.

## Included in this MVP

- Cluster inventory and global health dashboard
- API Gateway connectivity checks per deployment
- Encrypted-at-rest ISE passwords (Fernet master key supplied at runtime)
- TLS verification and optional private-CA bundle support
- ERS client methods for network-device reads and writes
- Audit log for connectivity and administrative actions
- Demo mode with realistic cluster data

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:ISE_PORTAL_MASTER_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ISE_PORTAL_DEMO = "1"
flask --app app run
```

Open `http://127.0.0.1:5000`.

## Production prerequisites

1. Enable the ISE API Gateway and the required ERS/OpenAPI services on each deployment.
2. Use a dedicated least-privilege API account per cluster; keep read and write identities separate where practical.
3. Trust each deployment's issuing CA. Do not disable TLS verification in production.
4. Put the portal behind enterprise SSO and a reverse proxy. The MVP intentionally does not invent a local identity system.
5. Replace SQLite with PostgreSQL, store secrets in an enterprise vault, run background health/drift jobs, and require approval for bulk writes.

## Safe expansion path

Add read-only cross-cluster views first (network devices, identity groups, endpoints, TrustSec objects), then desired-state comparison, then dry-run plans and approval-gated writes. API/version capability discovery should prevent a policy from being sent to a cluster that cannot represent it.
