# Sentinel Log SIEM

Python security monitoring experiments and log analysis utilities.

## Projects

### [SSH Brute Force Detector](projects/ssh-brute-force-detector)

Offline analysis of Linux SSH authentication logs using a configurable sliding window. Supports IPv4/IPv6 sources, JSON findings, synthetic sample data, and automated tests.

~~~bash
cd projects/ssh-brute-force-detector
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026
python -m unittest discover -s tests -v
~~~

### [Original SIEM prototype](siem_motoru.py)

The initial SIEM prototype and its sample log file are at the repository root. See [original notes](read.md).

Each project can be explored separately.
