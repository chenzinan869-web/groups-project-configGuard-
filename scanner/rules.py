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