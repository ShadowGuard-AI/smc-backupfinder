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

## License
Copyright (c) ShadowGuardAI
