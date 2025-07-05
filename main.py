import argparse
import logging
import os
import re
import sys
import yaml
import json
from jsonschema import validate, ValidationError, SchemaError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common backup file extensions
BACKUP_EXTENSIONS = ['.bak', '.old', '~', '.swp']

# Define common config file extensions
CONFIG_EXTENSIONS = ['.yaml', '.yml', '.json']

def setup_argparse():
    """
    Sets up the argument parser for the tool.
    """
    parser = argparse.ArgumentParser(description='smc-BackupFinder: Security Misconfiguration Scanner')
    parser.add_argument('-t', '--target', help='Target directory to scan. Defaults to current directory.', default='.')
    parser.add_argument('-c', '--config', help='Configuration file for security misconfiguration checks (YAML/JSON).', required=False)
    parser.add_argument('-b', '--backup', action='store_true', help='Enable backup file scanning.', default=False)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')

    return parser.parse_args()

def find_backup_files(target_dir):
    """
    Finds backup files in the specified directory.

    Args:
        target_dir (str): The directory to search in.

    Returns:
        list: A list of file paths to backup files.
    """
    backup_files = []
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                for ext in BACKUP_EXTENSIONS:
                    if file.endswith(ext) or re.match(r'^\..*\.swp$', file): #covers .*.swp files as well
                        file_path = os.path.join(root, file)
                        backup_files.append(file_path)
                        break # Avoid duplicate matches if a file has multiple backup extensions.

        return backup_files
    except OSError as e:
        logging.error(f"Error accessing directory {target_dir}: {e}")
        return []  # Return an empty list to avoid further errors.
    except Exception as e:
        logging.error(f"An unexpected error occurred during backup file search: {e}")
        return [] # Return an empty list in case of unexpected errors

def load_config(config_file):
    """
    Loads the configuration file (YAML or JSON).

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: The configuration data as a dictionary, or None on error.
    """
    try:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                return yaml.safe_load(f)
            elif config_file.endswith('.json'):
                return json.load(f)
            else:
                logging.error("Unsupported configuration file format.  Use YAML or JSON.")
                return None
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading config: {e}")
        return None

def validate_config(config_data, schema):
    """
    Validates the configuration data against a JSON schema.

    Args:
        config_data (dict): The configuration data.
        schema (dict): The JSON schema for validation.

    Returns:
        bool: True if the configuration is valid, False otherwise.
    """
    try:
        validate(instance=config_data, schema=schema)
        return True
    except ValidationError as e:
        logging.error(f"Configuration validation error: {e}")
        return False
    except SchemaError as e:
        logging.error(f"Schema error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during schema validation: {e}")
        return False

def scan_config_files(target_dir, config_rules):
    """
    Scans configuration files for security misconfigurations based on the rules.

    Args:
        target_dir (str): The directory to scan.
        config_rules (list): A list of rules to apply for scanning.
    """
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                if any(file.endswith(ext) for ext in CONFIG_EXTENSIONS):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for rule in config_rules:
                                # Example rule format: {'name': 'Exposed API Key', 'regex': 'API_KEY = ".*?"'}
                                rule_name = rule.get('name', 'Unnamed Rule')
                                regex = rule.get('regex')

                                if not regex:
                                    logging.warning(f"Rule '{rule_name}' has no regex defined. Skipping.")
                                    continue

                                matches = re.findall(regex, content)
                                if matches:
                                    logging.warning(f"Potential security misconfiguration in {file_path}: Rule '{rule_name}' matched: {matches}")

                    except OSError as e:
                        logging.error(f"Error reading file {file_path}: {e}")
                    except Exception as e:
                        logging.error(f"An unexpected error occurred while scanning {file_path}: {e}")

    except OSError as e:
        logging.error(f"Error accessing directory {target_dir}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during config file scanning: {e}")

def main():
    """
    Main function of the smc-BackupFinder tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target_directory = args.target

    if not os.path.isdir(target_directory):
        logging.error(f"Target directory '{target_directory}' is not a valid directory.")
        sys.exit(1)
    
    if args.backup:
        logging.info("Scanning for backup files...")
        backup_files = find_backup_files(target_directory)

        if backup_files:
            logging.warning("Found the following backup files:")
            for file_path in backup_files:
                logging.warning(f"  - {file_path}")
        else:
            logging.info("No backup files found.")

    if args.config:
        logging.info("Scanning for security misconfigurations...")
        config_file = args.config
        config_data = load_config(config_file)

        if config_data:
            # Basic schema for config validation (expand as needed)
            config_schema = {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "regex": {"type": "string"}
                    },
                    "required": ["name", "regex"]
                }
            }

            if validate_config(config_data, config_schema):
                scan_config_files(target_directory, config_data)
            else:
                logging.error("Configuration file validation failed.  Please check the file format and schema.")
        else:
            logging.error("Failed to load configuration file.")


if __name__ == "__main__":
    main()