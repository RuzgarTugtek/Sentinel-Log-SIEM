# SSH Brute Force Detector

A small defensive Python CLI for detecting repeated failed SSH password attempts in Linux syslog/auth.log files. It performs offline analysis only: no network connections, credential checks, or blocking actions.

## Features

- Extract failed SSH password attempts and validate IPv4/IPv6 addresses.
- Group attempts per source IP using a configurable sliding time window.
- Output a human-readable summary or machine-readable JSON.
- Ignore malformed and unrelated log lines.
- Run with Python 3.10+ and the standard library only.

## Quick start

From this project's directory:

~~~bash
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026 --json
~~~

Example finding using the bundled synthetic log:

~~~text
198.51.100.23  |  4 attempts  |  2026-11-14T10:00:00  ->  2026-11-14T10:03:00
~~~

## Tests

~~~bash
python -m unittest discover -s tests -v
~~~

## Detection notes

Input format: traditional syslog SSH messages such as "Nov 14 10:01:00 host sshd[123]: Failed password for root from 198.51.100.23 port 53000 ssh2". Set --year to match the log year. Records from one calendar year are supported; ISO 8601 and journald JSON formats are not supported.

The tool counts only "Failed password" events, avoiding double counting accompanying "Invalid user" messages. Findings report the largest matching window for each IP; a finding is an indicator for analyst review, not proof of malicious intent. Rotated logs and year boundaries should be analyzed separately.

All sample addresses are documentation-only TEST-NET addresses. Avoid publishing real authentication logs or sensitive identifiers.

## Project structure

- ssh_detector/core.py: parsing and detection logic
- ssh_detector/__main__.py: CLI
- tests/: unit tests
- samples/: synthetic SSH log events

This project complements the repository's existing SIEM log analysis prototype.
