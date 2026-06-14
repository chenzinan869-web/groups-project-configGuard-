"""
T-18 | tests/test_rules.py
Unit tests for all five Sprint 1 ConfigGuard rules.

Run with:
    pytest tests/test_rules.py -v
"""

import pytest
from scanner.rules import (
    check_privileged_mode,
    check_exposed_ports,
    check_latest_image_tag,
    check_resource_limits,
    check_hardcoded_secrets,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def services(*dicts):
    """Build a services dict from a list of (name, config) pairs."""
    return dict(dicts)


# ===========================================================================
# Rule 1 — Privileged mode
# ===========================================================================

class TestPrivilegedMode:

    def test_no_privileged_flag_clean(self):
        result = check_privileged_mode(services(("web", {"image": "nginx:1.25"})))
        assert result == []

    def test_privileged_true_flagged(self):
        result = check_privileged_mode(services(("app", {"image": "myapp:1.0", "privileged": True})))
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"
        assert result[0]["service"] == "app"

    def test_privileged_false_clean(self):
        result = check_privileged_mode(services(("db", {"image": "postgres:15", "privileged": False})))
        assert result == []

    def test_only_privileged_service_flagged(self):
        svcs = services(
            ("web",   {"image": "nginx:1.25"}),
            ("admin", {"image": "busybox", "privileged": True}),
        )
        result = check_privileged_mode(svcs)
        assert len(result) == 1
        assert result[0]["service"] == "admin"

    def test_empty_services_returns_empty(self):
        assert check_privileged_mode({}) == []


# ===========================================================================
# Rule 2 — Dangerous exposed ports
# ===========================================================================

class TestExposedPorts:

    def test_safe_port_clean(self):
        svcs = services(("web", {"image": "nginx:1.25", "ports": ["80:80", "443:443"]}))
        assert check_exposed_ports(svcs) == []

    def test_no_ports_clean(self):
        assert check_exposed_ports(services(("web", {"image": "nginx:1.25"}))) == []

    def test_mysql_port_globally_exposed_flagged(self):
        svcs = services(("db", {"image": "mysql:8.0", "ports": ["3306:3306"]}))
        result = check_exposed_ports(svcs)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"

    def test_ssh_port_exposed_flagged(self):
        svcs = services(("bastion", {"image": "openssh", "ports": ["22:22"]}))
        result = check_exposed_ports(svcs)
        assert len(result) == 1

    def test_localhost_bind_clean(self):
        # 127.0.0.1 binding is safe — should not be flagged
        svcs = services(("db", {"image": "postgres:15", "ports": ["127.0.0.1:5432:5432"]}))
        assert check_exposed_ports(svcs) == []

    def test_multiple_dangerous_ports_all_flagged(self):
        svcs = services(("db", {"image": "mysql:8.0", "ports": ["3306:3306", "6379:6379"]}))
        result = check_exposed_ports(svcs)
        assert len(result) == 2


# ===========================================================================
# Rule 3 — Latest image tag
# ===========================================================================

class TestLatestImageTag:

    def test_pinned_tag_clean(self):
        svcs = services(
            ("web", {"image": "nginx:1.25.3"}),
            ("db",  {"image": "postgres:15.2"}),
        )
        assert check_latest_image_tag(svcs) == []

    def test_latest_tag_flagged(self):
        svcs = services(("cache", {"image": "redis:latest"}))
        result = check_latest_image_tag(svcs)
        assert len(result) == 1
        assert result[0]["service"] == "cache"
        assert result[0]["severity"] == "MEDIUM"

    def test_no_tag_flagged(self):
        # "nginx" with no tag implicitly pulls latest
        svcs = services(("web", {"image": "nginx"}))
        result = check_latest_image_tag(svcs)
        assert len(result) == 1

    def test_sha256_digest_clean(self):
        svcs = services(("app", {"image": "myapp@sha256:abc123def456"}))
        assert check_latest_image_tag(svcs) == []

    def test_stable_tag_flagged(self):
        svcs = services(("cache", {"image": "redis:stable"}))
        result = check_latest_image_tag(svcs)
        assert len(result) == 1

    def test_multiple_mutable_tags_all_flagged(self):
        svcs = services(
            ("web",   {"image": "nginx:latest"}),
            ("app",   {"image": "myapp:main"}),
            ("proxy", {"image": "traefik:2.10"}),  # pinned — clean
        )
        result = check_latest_image_tag(svcs)
        assert len(result) == 2


# ===========================================================================
# Rule 4 — Missing resource limits
# ===========================================================================

class TestResourceLimits:

    def test_with_limits_clean(self):
        svcs = services(("web", {
            "image": "nginx:1.25",
            "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}},
        }))
        assert check_resource_limits(svcs) == []

    def test_missing_deploy_flagged(self):
        svcs = services(("db", {"image": "postgres:15"}))
        result = check_resource_limits(svcs)
        assert len(result) == 1
        assert result[0]["severity"] == "MEDIUM"
        assert result[0]["service"] == "db"

    def test_missing_limits_block_flagged(self):
        svcs = services(("db", {
            "image": "postgres:15",
            "deploy": {"resources": {}},
        }))
        result = check_resource_limits(svcs)
        assert len(result) == 1

    def test_multiple_services_all_missing_limits(self):
        svcs = services(
            ("web",   {"image": "nginx:1.25"}),
            ("cache", {"image": "redis:7.2"}),
        )
        result = check_resource_limits(svcs)
        assert len(result) == 2

    def test_only_service_missing_limits_flagged(self):
        svcs = services(
            ("web", {
                "image": "nginx:1.25",
                "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "128M"}}},
            }),
            ("db", {"image": "postgres:15"}),  # no limits
        )
        result = check_resource_limits(svcs)
        assert len(result) == 1
        assert result[0]["service"] == "db"


# ===========================================================================
# Rule 5 — Hardcoded secrets
# ===========================================================================

class TestHardcodedSecrets:

    def test_variable_reference_clean(self):
        svcs = services(("db", {
            "image": "postgres:15",
            "environment": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"},
        }))
        assert check_hardcoded_secrets(svcs) == []

    def test_hardcoded_password_flagged(self):
        svcs = services(("db", {
            "image": "postgres:15",
            "environment": {"DB_PASSWORD": "supersecret123"},
        }))
        result = check_hardcoded_secrets(svcs)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"
        assert result[0]["service"] == "db"

    def test_empty_password_clean(self):
        # Empty value — nothing to leak
        svcs = services(("db", {
            "image": "postgres:15",
            "environment": {"DB_PASSWORD": ""},
        }))
        assert check_hardcoded_secrets(svcs) == []

    def test_non_secret_key_clean(self):
        svcs = services(("web", {
            "image": "nginx:1.25",
            "environment": {"APP_ENV": "production", "PORT": "8080"},
        }))
        assert check_hardcoded_secrets(svcs) == []

    def test_list_format_environment_flagged(self):
        # docker-compose also allows environment as a list of KEY=VALUE strings
        svcs = services(("db", {
            "image": "mysql:8.0",
            "environment": ["DB_PASSWORD=mysecret", "APP_ENV=prod"],
        }))
        result = check_hardcoded_secrets(svcs)
        assert len(result) == 1
        assert result[0]["service"] == "db"

    def test_api_key_flagged(self):
        svcs = services(("app", {
            "image": "myapp:1.0",
            "environment": {"API_KEY": "sk-abc123realkey"},
        }))
        result = check_hardcoded_secrets(svcs)
        assert len(result) == 1
