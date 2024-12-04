import nmap
import re

# Validate IP address format
def validate_ip(ip):
    
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None

# Validate port range format (Ex: '1-1000' or '80,443')
def validate_ports(ports):
    
    return re.match(r'^\d{1,5}(-\d{1,5})?$|^(\d{1,5},)+\d{1,5}$', ports) is not None

# Scan for open ports
def scan_target(target, ports):
    scanner = nmap.PortScanner()
    print(f"\nStarting stealth scan on {target} for ports {ports}...\n")
    
    try:
        # Perform the scan
        scanner.scan(hosts=target, ports=ports, arguments="-sS -Pn")
        
        open_ports = []
        if scanner.all_hosts():
            for host in scanner.all_hosts():
                print(f"Host: {host} ({scanner[host].hostname() or 'N/A'}) | State: {scanner[host].state()}")
                open_ports = [
                    port for port in sorted(scanner[host]['tcp'].keys()) 
                    if scanner[host]['tcp'][port]['state'] == 'open'
                ]
                print(f"\nOpen Ports Detected: {', '.join(map(str, open_ports))}\n")
        
        return open_ports

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        return []

    except Exception as e:
        print(f"Error during scan: {e}")
        return []

# Detect the OS of the target
def check_os(target):
    print(f"\nStarting OS detection on {target}...\n")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, arguments="-O -Pn")
        for host in scanner.all_hosts():
            os_info = scanner[host].get('osmatch', [])
            if os_info:
                print(f"Possible OS: {os_info[0]['name']}")
            else:
                print(f"No OS information found.")
    except KeyboardInterrupt:
        print("\nOS detection interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error during OS detection: {e}")

# Detect services and versions
def check_services(target, ports):
    print(f"\nStarting service version detection on {target} for ports {ports}...\n")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, ports=ports, arguments="-sV -Pn")
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    port_info = scanner[host][proto][port]
                    service_name = port_info['name']
                    version_info = port_info.get('version', 'N/A')
                    print(f"Port: {port} | State: {port_info['state']} | Service: {service_name} | Version: {version_info}")
    except KeyboardInterrupt:
        print("\nService detection interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error during service detection: {e}")

# Run a vulnerability scan
def run_vuln_scan(target, ports):
    print(f"\nRunning vulnerability scan on {target} for ports {ports}...\n")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, ports=ports, arguments="--script=vuln -Pn")
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    print(f"Port {port}:")
                    for script in scanner[host][proto][port].get('script', []):
                        print(f"  - {script}")
    except KeyboardInterrupt:
        print("\nVulnerability scan interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")

# SSL/TLS certificate check
def check_ssl(target, ports):
    print(f"\nStarting SSL/TLS certificate check on {target} for ports {ports}...\n")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, ports=ports, arguments="--script ssl-cert,ssl-enum-ciphers -Pn")
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    print(f"Port {port}:")
                    for script in scanner[host][proto][port].get('script', []):
                        print(f"  - {script}")
    except KeyboardInterrupt:
        print("\nSSL/TLS certificate check interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error during SSL/TLS check: {e}")

# Interactive menu
def interactive_menu(target, open_ports):
    while True:
        print("1. OS detection")
        print("2. Service version detection")
        print("3. Vulnerability scan")
        print("4. SSL/TLS certificate check")
        print("5. Exit")
        
        try:
            choice = input("Select an option > ").strip()

            if choice == '1':
                check_os(target)
            elif choice == '2':
                check_services(target, ",".join(map(str, open_ports)))
            elif choice == '3':
                run_vuln_scan(target, ",".join(map(str, open_ports)))
            elif choice == '4':
                check_ssl(target, ",".join(map(str, open_ports)))
            elif choice == '5':
                print("Exiting...")
                break
            else:
                print("Invalid choice! Please enter a valid option.")
        except KeyboardInterrupt:
            print("\nUser interrupted. Exiting...")
            break
        except Exception as e:
            print(f"Error during menu selection: {e}")

# Main entry point
if __name__ == "__main__":
    try:
        target = input("Enter the target (IP or hostname) > ").strip()
        
        if not validate_ip(target):
            print("Invalid IP address format. Please enter a valid IP.")
            exit(1)
        
        ports = input("Enter the port range to scan (Ex: 1-1000) > ").strip()
        
        if not validate_ports(ports):
            print("Invalid port range format. Please enter a valid port range.")
            exit(1)

        open_ports = scan_target(target, ports)

        if open_ports:
            interactive_menu(target, open_ports)
        else:
            print("No open ports detected. Exiting...")

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error during script execution: {e}")
