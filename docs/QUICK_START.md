# Quick start: return after a hiatus

Reviewed: 2026-11-01. Read [Status](STATUS.md) first. For context use [Blueprint](BLUEPRINT.md); for details use [Handbook](HANDBOOK.md).

## 1. Reorient

From the repository root, inspect before pulling or switching branches:

```text
git status --short
git log -5 --oneline
git remote -v
```

Read the last validation, open issues, and next step in STATUS. GitHub holds source; database and secrets are separate.

## 2. Prepare the runtime

Use Python 3.12 on both RHEL environments. Create a virtual environment only if absent; install dependencies on setup or requirements changes.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe --version
```

If `py` is unavailable use the installed Python 3.12 executable. Existing Windows environment metadata reports 3.14.2; do not overwrite it without planning recovery. Use a separate environment if needed and substitute its path below.

RHEL:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python --version
```

Recreate environments per host; never copy `.venv` between operating systems/servers.

## 3. Choose isolated demo or real inventory

Disposable demo, Windows:

```powershell
$env:DATABASE_URL = "sqlite:///resume-demo.db"
$env:FLASK_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$env:ISE_PORTAL_MASTER_KEY = .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ISE_PORTAL_DEMO = "1"
.\.venv\Scripts\python.exe -m flask --app app run --debug
```

Disposable demo, RHEL:

```bash
export DATABASE_URL='sqlite:///resume-demo.db'
export FLASK_SECRET_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export ISE_PORTAL_MASTER_KEY="$(.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export ISE_PORTAL_DEMO=1
.venv/bin/python -m flask --app app run --debug
```

Use these only for disposable sample data; do not save real credentials in this demo. Demo mode alone is not isolation: real clusters with encrypted credentials can still contact ISE.

For real inventory instead: restore the original database URL, original master key and persistent Flask secret from your approved secret source; set `ISE_PORTAL_DEMO=0`. **Never generate a replacement master key just to restart an existing real database.** Read [persistent state](HANDBOOK.md#configuration-and-persistent-state).

Open http://127.0.0.1:5000. Ctrl+C stops the app. Calling Python directly bypasses the Windows `flask.cmd` batch wrapper and its termination confirmation. Debug mode is for local development only.

## 4. Verify and resume

In another terminal at the repository root:

```powershell
# Windows
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

```bash
# RHEL
.venv/bin/python -m pytest -q -p no:cacheprovider
```

Inspect demo dashboard, details, certificate and audit pages. Tests use in-memory databases and mocked APIs; they do not prove live ISE or RHEL compatibility. Do not use real certificate imports as a startup check.

Follow the next task in STATUS, using Blueprint's source map. Before stopping, update affected guides and STATUS with actual results, remaining work and the next concrete step. Follow [AGENTS.md](../AGENTS.md).
