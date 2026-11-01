# smc-BackupFinder
Attempts to locate common backup file names (e.g., *.bak, *.old, ~*, .*.swp) in the web root. Reports any found files, highlighting the risk of sensitive data exposure. - Focused on Scans common application configurations (e.g., YAML, JSON files) for security misconfigurations.  Uses a rule-based engine defined in YAML or JSON schemas to identify potential vulnerabilities such as exposed API keys, default credentials, or overly permissive permissions. Designed for scanning local application configurations.

## Install
`git clone https://github.com/ShadowGuardAI/smc-backupfinder`

## Usage
`./smc-backupfinder [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: Target directory to scan. Defaults to current directory.
- `-c`: No description provided
- `-b`: Enable backup file scanning.
- `-v`: No description provided

## Behaviour notes

Running with neither `-b` nor `-c` is a usage error and exits with status 2. A malformed, missing, or empty configuration file, and a configuration that fails validation, exit with status 1. Config scan warnings name the rule, the file, and the match count only; matched values are never printed. Every completed scan ends with a summary line giving files scanned and matches found, and a directory walk error is reported as an error and fails the run.

## License
Copyright (c) ShadowGuardAI
