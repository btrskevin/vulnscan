# Python Port Scanner

This Python script automates various Nmap scan tasks, making it easier for beginners to execute port scans through an interactive and friendly menu.

## Disclaimer:

This script should only be used on networks and devices you own or have explicit permission to scan. Unauthorized scanning is illegal and unethical.

## Features:

- **OS Detection**: Identifies the operating system of the target.
- **Service Version Detection**: Detects the versions of services running on open ports.
- **Vulnerability Scan**: Checks for known vulnerabilities on open ports.
- **SSL/TLS Certificate Checks**: Analyzes SSL/TLS certificates and supported cipher suites for secure connections.

## Instructions:

1. git clone https://github.com/btrskevin/vulnscan
2. Download and install Nmap through https://nmap.org/download.html
3. pip install python-nmap

## Usage:

1. python main.py
2. Enter the target IP address or hostname
3. Enter the port range to scan
4. Select between various extra scanning features