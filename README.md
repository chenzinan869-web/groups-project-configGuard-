# ConfigGuard

A lightweight command-line tool that scans `docker-compose.yml` files for security misconfigurations. It detects dangerous settings, explains each risk in plain language, and suggests a concrete fix — no security expertise required.

---

## What it detects

| Rule | Severity |
|------|----------|
| Privileged mode enabled | HIGH |
| Sensitive ports exposed to all interfaces | HIGH |
| Hardcoded secrets in environment variables | HIGH |
| Unpinned image tags (latest, stable, etc.) | MEDIUM |
| Missing CPU / memory resource limits | MEDIUM |

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
python3 main.py --file path/to/docker-compose.yml
```

**Options:**

| Flag | Description |
|------|-------------|
| `--file` | Path to the docker-compose.yml file to scan (required) |
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
│ HIGH     │   2   │
│ MEDIUM   │   1   │
│ LOW      │   0   │
│ TOTAL    │   3   │
╰──────────┴───────╯
```

---

## Running against the test fixtures

```bash
# Should detect 12 issues
python3 main.py --file tests/test_fixture.yml

# Should detect 0 issues
python3 main.py --file tests/good_fixture.yml
```

---

## Project structure

```
groups-project-configGuard-/
├── main.py                  # Entry point
├── requirements.txt
├── scanner/
│   ├── parser.py            # YAML file loader
│   ├── rules.py             # Detection rules
│   ├── output.py            # Terminal output (rich)
│   └── exporter.py          # JSON / HTML export
└── tests/
    ├── test_fixture.yml     # Misconfigured file (all rules should fire)
    └── good_fixture.yml     # Clean file (no rules should fire)
```

---

## Course

IN-CST-CMK — Fontys ICT  
Team: Noud Peters, Aymane Derkaoui, Zinan Chen, Abdirahman Hassan
