import yaml
import sys

def parse_compose_file(file_path):
    """Load and parse a docker-compose.yml file. Exits cleanly on error."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: File not found: '{file_path}'")
        print("Make sure the path is correct and the file exists.")
        sys.exit(2)
    except yaml.YAMLError as e:
        print(f"Error: Could not parse '{file_path}' — invalid YAML.")
        print(f"Details: {e}")
        sys.exit(2)

    if data is None or 'services' not in data:
        print(f"Error: No 'services' block found in '{file_path}'.")
        print("Make sure this is a valid docker-compose.yml file.")
        sys.exit(2)

    return data['services']