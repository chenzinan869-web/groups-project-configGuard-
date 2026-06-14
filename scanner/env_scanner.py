"""
T-17 | scanner/env_scanner.py
Scans .env files for security issues: hardcoded secrets, placeholder values,
empty credentials, and debug flags left enabled.
"""

import re
import os

# Variable name patterns that suggest a secret or credential
SECRET_KEY_PATTERNS = re.compile(
    r"(PASSWORD|PASSWD|PWD|API_KEY|APIKEY|API_SECRET|SECRET|TOKEN|AUTH"
    r"|PRIVATE_KEY|ACCESS_KEY|ACCESS_SECRET|DB_PASS|DATABASE_URL|SMTP_PASS)",
    re.IGNORECASE,
)

# Values that are clearly placeholders left in by developers
PLACEHOLDER_PATTERNS = [
    re.compile(r"^(changeme|change_me|change-me)$", re.IGNORECASE),
    re.compile(r"^(your[-_]?(key|secret|password|token))$", re.IGNORECASE),
    re.compile(r"^(todo|fixme|xxx+|placeholder|replace[-_]?me)$", re.IGNORECASE),
    re.compile(r"^(pass(word)?|admin|root|test|example|demo|default)$", re.IGNORECASE),
    re.compile(r"^(1234|12345|123456|password123|qwerty)$", re.IGNORECASE),
    re.compile(r"^<.+>$"),    # <YOUR_SECRET_HERE>
    re.compile(r"^\[.+\]$"),  # [insert token]
]

# A variable reference like ${MY_VAR} is safe — the real value stays out of the file
VARIABLE_REF = re.compile(r"^\$\{.+\}$")


def _is_placeholder(value):
    """Return True if the value looks like a developer placeholder."""
    return any(p.match(value) for p in PLACEHOLDER_PATTERNS)


def _parse_env_file(filepath):
    """Parse a .env file and return (line_number, key, value) tuples.

    Skips comments and blank lines.
    """
    entries = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip().strip('"').strip("'")
            entries.append((lineno, key, value))
    return entries


def scan_env_file(filepath):
    """Scan a single .env file and return a list of findings.

    Args:
        filepath (str): Path to the .env file.

    Returns:
        list[dict]: Findings with keys rule, service, severity, description, fix.
    """
    findings = []

    if not os.path.isfile(filepath):
        return findings

    filename = os.path.basename(filepath)
    entries  = _parse_env_file(filepath)

    for lineno, key, value in entries:
        is_secret_key = bool(SECRET_KEY_PATTERNS.search(key))

        # Check 1 - Sensitive key with an empty value
        if is_secret_key and value == "":
            findings.append({
                "rule":        "Empty secret in .env",
                "service":     filename,
                "severity":    "MEDIUM",
                "description": f"'{key}' (line {lineno}) looks like a credential but has an empty value. "
                               "Services may fall back to insecure defaults or skip authentication.",
                "fix":         f"Set a real value for {key} or remove the entry if it is unused.",
            })

        # Check 2 - Sensitive key with a placeholder value
        elif is_secret_key and value and _is_placeholder(value):
            findings.append({
                "rule":        "Placeholder secret in .env",
                "service":     filename,
                "severity":    "HIGH",
                "description": f"'{key}' (line {lineno}) is set to a placeholder value ('{value}'). "
                               "This credential is not real and will cause failures or security issues in production.",
                "fix":         f"Replace '{value}' with the real secret value and ensure the .env file "
                               "is listed in .gitignore so it is never committed.",
            })

        # Check 3 - Sensitive key with a hardcoded literal (not a ${VAR} reference)
        elif is_secret_key and value and not VARIABLE_REF.match(value) and not _is_placeholder(value):
            findings.append({
                "rule":        "Hardcoded secret in .env",
                "service":     filename,
                "severity":    "MEDIUM",
                "description": f"'{key}' (line {lineno}) contains a hardcoded literal secret. "
                               "If this file is ever committed to version control the secret will be exposed.",
                "fix":         f"Ensure {filepath} is in .gitignore. "
                               f"For shared environments, store secrets in a secrets manager "
                               f"and reference them via ${{{key}}}.",
            })

        # Check 4 - Debug / development mode enabled
        if re.search(r"^(DEBUG|FLASK_DEBUG|DJANGO_DEBUG)$", key, re.IGNORECASE):
            if value.lower() in ("true", "1", "yes", "on"):
                findings.append({
                    "rule":        "Debug mode enabled in .env",
                    "service":     filename,
                    "severity":    "MEDIUM",
                    "description": f"'{key}' (line {lineno}) is set to '{value}'. "
                                   "Debug mode exposes stack traces and internal config, "
                                   "and may disable security controls in production.",
                    "fix":         f"Set {key}=false (or remove it) before deploying to production.",
                })

    return findings
