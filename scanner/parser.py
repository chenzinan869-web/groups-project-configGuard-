import yaml

def parse_compose_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('services', {})