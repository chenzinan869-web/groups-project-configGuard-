# T-06: Detection rule - Privileged mode enabled
def check_privileged_mode(services):
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
DANGEROUS_PORTS = ["22", "3306", "5432", "27017", "6379", "9200"]

def check_exposed_ports(services):
    findings = []

    for service_name, service_config in services.items():
        ports = service_config.get("ports", [])
        for port in ports:
            host_port = str(port).split(":")[0]
            if host_port in DANGEROUS_PORTS:
                findings.append({
                    "rule": "Dangerous port exposed",
                    "service": service_name,
                    "severity": "HIGH",
                    "description": f"Port {host_port} is exposed to the host.",
                    "fix": "Remove the port mapping or restrict it to localhost only e.g. 127.0.0.1:3306:3306"
                })

    return findings
# T-08: Detection rule - Latest image tag
def check_latest_image_tag(services):
    findings = []

    for service_name, service_config in services.items():
        image = service_config.get("image", "")
        if image.endswith(":latest") or ":" not in image:
            findings.append({
                "rule": "Latest image tag used",
                "service": service_name,
                "severity": "MEDIUM",
                "description": f"Service '{service_name}' uses an unpinned image tag.",
                "fix": "Pin the image to a specific version e.g. nginx:1.25.3"
            })

    return findings 
# T-09: Detection rule - Missing resource limits
def check_resource_limits(services):
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
import re

SECRET_PATTERNS = [
    r"(?i)password=\S+",
    r"(?i)api_key=\S+",
    r"(?i)secret=\S+",
    r"(?i)token=\S+",
    r"(?i)db_pass=\S+"
]

def check_hardcoded_secrets(services):
    findings = []

    for service_name, service_config in services.items():
        env_vars = service_config.get("environment", [])
        if isinstance(env_vars, dict):
            env_vars = [f"{k}={v}" for k, v in env_vars.items()]

        for var in env_vars:
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, var):
                    findings.append({
                        "rule": "Hardcoded secret detected",
                        "service": service_name,
                        "severity": "HIGH",
                        "description": f"Possible secret found in environment variable: {var}",
                        "fix": "Use a .env file or Docker secrets instead of hardcoding credentials."
                    })
                    break

    return findings