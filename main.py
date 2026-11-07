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
    files_scanned = 0
    walk_errors = []

    def on_walk_error(error):
        logging.error(f"Error walking directory: {error}")
        walk_errors.append(error)

    try:
        for root, _, files in os.walk(target_dir, onerror=on_walk_error):
            for file in files:
                files_scanned += 1
                for ext in BACKUP_EXTENSIONS:
                    # Two of these three tests do not involve ext at all, so the loop over extensions is doing less than it looks: the prefix and swap tests would match on the first pass regardless. The break below is what saves a tilde file from being added once per extension.
                    if file.endswith(ext) or file.startswith('~') or re.match(r'^\..*\.swp$', file): #covers .*.swp files as well
                        file_path = os.path.join(root, file)
                        backup_files.append(file_path)
                        break # Avoid duplicate matches if a file has multiple backup extensions.

        if walk_errors:
            logging.error(f"Backup scan incomplete: {len(walk_errors)} walk error(s) occurred.")
            return None
        logging.info(f"End of scan summary: {files_scanned} files scanned, {len(backup_files)} matches found.")
        return backup_files
    except OSError as e:
        logging.error(f"Error accessing directory {target_dir}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during backup file search: {e}")
        return None

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
    files_scanned = 0
    total_matches = 0
    walk_errors = []

    def on_walk_error(error):
        logging.error(f"Error walking directory: {error}")
        walk_errors.append(error)

    for rule in config_rules:
        regex = rule.get('regex') if isinstance(rule, dict) else None
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                logging.error(f"Rule '{rule.get('name', 'Unnamed Rule')}' has an invalid regex: {e}")
                return False

    try:
        for root, _, files in os.walk(target_dir, onerror=on_walk_error):
            for file in files:
                if any(file.endswith(ext) for ext in CONFIG_EXTENSIONS):
                    file_path = os.path.join(root, file)
                    files_scanned += 1
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

                                # The rule pattern is recompiled from its string form for every file, and a pattern that is not valid regex fails inside this per file handler. One bad rule therefore logs an unexpected error once per config file in the tree instead of failing once at load time.
                                matches = re.findall(regex, content)
                                if matches:
                                    total_matches += len(matches)
                                    logging.warning(f"Potential security misconfiguration in {file_path}: Rule '{rule_name}' matched {len(matches)} time(s).")

                    except OSError as e:
                        logging.error(f"Error reading file {file_path}: {e}")
                    except Exception as e:
                        logging.error(f"An unexpected error occurred while scanning {file_path}: {e}")

        if walk_errors:
            logging.error(f"Config scan incomplete: {len(walk_errors)} walk error(s) occurred.")
            return False
        # A match count from findall counts matched groups as written by the pattern author, so two rules hunting the same secret in one file both add to the total. The summary number is matches across rules, not files with problems and not distinct secrets.
        logging.info(f"End of scan summary: {files_scanned} files scanned, {total_matches} matches found.")
        return True
    except OSError as e:
        logging.error(f"Error accessing directory {target_dir}: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during config file scanning: {e}")
        return False

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

    if not args.backup and not args.config:
        logging.error("No scan selected. Use -b for backup file scanning and/or -c <config> for config scanning.")
        sys.exit(2)

    if args.backup:
        logging.info("Scanning for backup files...")
        backup_files = find_backup_files(target_directory)

        if backup_files is None:
            logging.error("Backup file scan failed.")
            sys.exit(1)

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

        # This truthiness test merges two different situations into one failure line: a config that failed to load, and a config that loaded fine but is an empty list. An empty rule set is a legitimate, if pointless, input, yet I report it as a load failure and exit.
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
                if not scan_config_files(target_directory, config_data):
                    sys.exit(1)
            else:
                logging.error("Configuration file validation failed.  Please check the file format and schema.")
                sys.exit(1)
        else:
            logging.error("Failed to load configuration file.")
            sys.exit(1)


if __name__ == "__main__":
    main()