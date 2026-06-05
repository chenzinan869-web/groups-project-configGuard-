import re

# T-06: Detection rule - Privileged mode enabled
def check_privileged_mode(services):
    """Check for containers running with privileged mode enabled."""
    findings = []

    for service_name, service_config in services.items():
        if service_config.get('privileged') == True:
            findings.append({
                'rule': 'Privileged mode enabled',
                'service': service_name,
                'severity': 'HIGH',
                'description': 'Container runs with full root access on the host.',
                'fix': "Remove privileged: true from your service definition."
            })

    return findings


# T-07: Detection rule - Dangerous exposed ports
DANGEROUS_PORTS = {"22", "3306", "5432", "27017", "6379", "9200"}

def check_exposed_ports(services):
    """Check for sensitive ports exposed to all network interfaces."""
    findings = []

    for service_name, service_config in services.items():
        ports = service_config.get("ports", [])
        for port in ports:
            parts = str(port).split(":")
            # Format: "PORT:PORT" or "INTERFACE:PORT:PORT"
            if len(parts) == 3:
                interface = parts[0]
                host_port = parts[1]
            else:
                interface = "0.0.0.0"
                host_port = parts[0]

            if host_port in DANGEROUS_PORTS and interface != "127.0.0.1":
                findings.append({
                    "rule": "Dangerous port exposed",
                    "service": service_name,
                    "severity": "HIGH",
                    "description": f"Port {host_port} is exposed to all network interfaces.",
                    "fix": f"Restrict the port to localhost only: '127.0.0.1:{host_port}:{host_port}'"
                })

    return findings


# T-08: Detection rule - Unpinned image tag
MUTABLE_TAGS = {"latest", "stable", "master", "main", "edge"}

def check_latest_image_tag(services):
    """Check for services using mutable or unpinned image tags."""
    findings = []

    for service_name, service_config in services.items():
        image = service_config.get("image", "")

        # Images pinned by digest are safe
        if "@sha256:" in image:
            continue

        if ":" not in image:
            tag = "latest"  # No tag defaults to latest
        else:
            tag = image.split(":")[-1]

        if tag in MUTABLE_TAGS:
            findings.append({
                "rule": "Unpinned image tag used",
                "service": service_name,
                "severity": "MEDIUM",
                "description": f"Service '{service_name}' uses the '{tag}' tag which can change without warning.",
                "fix": "Pin the image to a specific version e.g. nginx:1.25.3"
            })

    return findings


# T-09: Detection rule - Missing resource limits
def check_resource_limits(services):
    """Check for services missing CPU or memory resource limits."""
    findings = []

    for service_name, service_config in services.items():
        deploy = service_config.get("deploy", {})
        resources = deploy.get("resources", {})
        limits = resources.get("limits", {})

        if not limits:
            findings.append({
                "rule": "Missing resource limits",
                "service": service_name,
                "severity": "MEDIUM",
                "description": f"Service '{service_name}' has no CPU or memory limits set.",
                "fix": "Add resource limits under deploy.resources.limits in your service definition."
            })

    return findings


# T-10: Detection rule - Hardcoded secrets
SECRET_KEY_PATTERN = re.compile(
    r"(PASSWORD|SECRET|API_KEY|TOKEN|DB_PASS|PRIVATE_KEY)", re.IGNORECASE
)
VARIABLE_REF = re.compile(r"^\$\{.+\}$")

def check_hardcoded_secrets(services):
    """Check for literal secret values hardcoded in environment variables."""
    findings = []

    for service_name, service_config in services.items():
        env_vars = service_config.get("environment", {})

        # Handle list format: ["KEY=VALUE", ...]
        if isinstance(env_vars, list):
            env_dict = {}
            for item in env_vars:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
                else:
                    env_dict[item] = None
        else:
            env_dict = env_vars

        for key, value in env_dict.items():
            # Only check keys that look like they hold a secret
            if not SECRET_KEY_PATTERN.search(key):
                continue
            # Skip empty or None values
            if value is None or str(value).strip() == "":
                continue
            # Skip variable references like ${MY_SECRET} — these are safe
            if VARIABLE_REF.match(str(value)):
                continue

            findings.append({
                "rule": "Hardcoded secret detected",
                "service": service_name,
                "severity": "HIGH",
                "description": f"'{key}' contains a hardcoded value instead of a variable reference.",
                "fix": f"Replace the value with a variable reference: {key}=${{{key}}} and store the real value in a .env file excluded from version control."
            })

    return findings