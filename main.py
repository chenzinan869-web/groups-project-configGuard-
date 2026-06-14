import argparse
from scanner.parser import parse_compose_file
from scanner.env_scanner import scan_env_file
from scanner.rules import (
    check_privileged_mode,
    check_exposed_ports,
    check_latest_image_tag,
    check_resource_limits,
    check_hardcoded_secrets
)
from scanner.output import print_findings, print_summary
from scanner.exporter import export_json, export_html

def main():
    parser = argparse.ArgumentParser(
        description="ConfigGuard - Docker Compose Security Scanner",
        epilog="Example: python main.py --file docker-compose.yml --export json"
    )
    parser.add_argument("--file", required=True, help="Path to docker-compose.yml")
    parser.add_argument("--env",  default=None,  help="Path to a .env file to scan for secrets")
    parser.add_argument("--export", choices=["json", "html"], help="Export results to a file")
    args = parser.parse_args()

    print(f"Scanning file: {args.file}\n")

    services = parse_compose_file(args.file)

    # Run all detection rules
    findings = []
    findings += check_privileged_mode(services)
    findings += check_exposed_ports(services)
    findings += check_latest_image_tag(services)
    findings += check_resource_limits(services)
    findings += check_hardcoded_secrets(services)

    # Optionally scan a .env file
    if args.env:
        print(f"Scanning .env file: {args.env}\n")
        findings += scan_env_file(args.env)

    # Show results via rich output
    print_findings(findings)
    print_summary(findings)

    if args.export == "json":
        export_json(findings, args.file)
    elif args.export == "html":
        export_html(findings, args.file)

if __name__ == "__main__":
    main()