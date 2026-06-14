# ConfigGuard

A lightweight command-line tool that scans `docker-compose.yml` files for security misconfigurations. It detects dangerous settings, explains each risk in plain language, and suggests a concrete fix — no security expertise required.

---

## What it detects

| Rule | Severity |
|------|----------|
| Privileged mode enabled | HIGH |
| Sensitive ports exposed to all interfaces | HIGH |
| Hardcoded secrets in environment variables | HIGH |
| Docker socket or sensitive host path mounted | HIGH |
| Placeholder secrets in .env file | HIGH |
| Unpinned image tags (latest, stable, etc.) | MEDIUM |
| Missing CPU / memory resource limits | MEDIUM |
| Empty or hardcoded credentials in .env file | MEDIUM |
| Debug mode enabled in .env file | MEDIUM |

---

## Requirements

- Python 3.10+
- pip

---

## Installation

```bash
# Clone the repository
git clone https://github.com/chenzinan869-web/groups-project-configGuard-.git
cd groups-project-configGuard-

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan a docker-compose.yml file
python3 main.py --file path/to/docker-compose.yml

# Also scan a .env file for secrets
python3 main.py --file path/to/docker-compose.yml --env path/to/.env

# Export results
python3 main.py --file path/to/docker-compose.yml --export json
python3 main.py --file path/to/docker-compose.yml --export html
```

**Options:**

| Flag | Description |
|------|-------------|
| `--file` | Path to the docker-compose.yml file to scan (required) |
| `--env` | Path to a .env file to scan for exposed secrets (optional) |
| `--export json` | Export results to `scan_results.json` |
| `--export html` | Export results to `scan_results.html` |

---

## Example output

```
Scanning file: docker-compose.yml

❌ [HIGH] Privileged mode enabled
  Service     : web
  Description : Container runs with full root access on the host.
  Fix         : Remove privileged: true from your service definition.

❌ [HIGH] Docker socket mounted
  Service     : web
  Description : Service 'web' mounts the Docker socket (/var/run/docker.sock).
                This grants the container full control over the Docker daemon.
  Fix         : Remove the Docker socket mount.

❌ [HIGH] Hardcoded secret detected
  Service     : db
  Description : 'DB_PASSWORD' contains a hardcoded value instead of a variable reference.
  Fix         : Replace the value with a variable reference: DB_PASSWORD=${DB_PASSWORD}
                and store the real value in a .env file excluded from version control.

⚠️ [MEDIUM] Unpinned image tag used
  Service     : web
  Description : Service 'web' uses the 'latest' tag which can change without warning.
  Fix         : Pin the image to a specific version e.g. nginx:1.25.3

    Scan Summary
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ HIGH     │   3   │
│ MEDIUM   │   1   │
│ LOW      │   0   │
│ TOTAL    │   4   │
╰──────────┴───────╯
```

---

## Running against the test fixtures

```bash
# Should detect multiple issues across all rules
python3 main.py --file tests/test_fixture.yml

# Should detect 0 issues
python3 main.py --file tests/good_fixture.yml
```

---

## Running the tests

```bash
pip install pytest
python -m pytest tests/test_rules.py -v
```

---

## Project structure

```
groups-project-configGuard-/
├── main.py                  # Entry point
├── requirements.txt
├── scanner/
│   ├── parser.py            # YAML file loader
│   ├── rules.py             # Detection rules (docker-compose)
│   ├── env_scanner.py       # Detection rules (.env files)
│   ├── output.py            # Terminal output (rich)
│   └── exporter.py          # JSON / HTML export
└── tests/
    ├── test_rules.py        # Pytest unit tests for all rules
    ├── test_fixture.yml     # Misconfigured file (all rules should fire)
    └── good_fixture.yml     # Clean file (no rules should fire)
```

---

## Course

IN-CST-CMK — Fontys ICT  
Team: Noud Peters, Aymane Derkaoui, Zinan Chen, Abdirahman Hassan
