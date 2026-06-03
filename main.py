import argparse
from scanner.parser import parse_compose_file
from scanner.rules import check_privileged_mode

def main():
    parser = argparse.ArgumentParser(description="ConfigGuard - Docker Compose Security Scanner")
    parser.add_argument("--file", required=True, help="Path to docker-compose.yml")
    args = parser.parse_args()

    print(f"Scanning file: {args.file}\n")

    # Parse the file
    services = parse_compose_file(args.file)

    # Run detection rule
    findings = check_privileged_mode(services)

    # Show results
    if findings:
        for finding in findings:
            print(f"[{finding['severity']}] {finding['rule']}")
            print(f"  Service     : {finding['service']}")
            print(f"  Description : {finding['description']}")
            print(f"  Fix         : {finding['fix']}\n")
    else:
        print("No issues found!")

if __name__ == "__main__":
    main()