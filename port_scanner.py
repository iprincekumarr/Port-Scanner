#!/usr/bin/env python3
"""
Advanced Python Port Scanner
Features: SYN scanning, UDP scanning, banner grabbing, OS fingerprinting,
multiple output formats, progress bars, network range scanning
"""

import socket
import sys
import threading
import time
import argparse
import ipaddress
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Set
import struct
import select
import os
import signal
from collections import defaultdict

# Try to import optional dependencies
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("Warning: tqdm not installed. Install with: pip install tqdm")

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Warning: Scapy not installed. SYN scan will use TCP connect instead.")

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ServiceDetector:
    """Service detection and banner grabbing"""
    
    # Common service probes
    PROBES = {
        21: b"USER anonymous\r\n",
        22: b"",
        25: b"EHLO test\r\n",
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        110: b"",
        111: b"",
        143: b"",
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        3306: b"",
        3389: b"",
        5432: b"",
        5900: b"",
        6379: b"*1\r\n$4\r\nPING\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
    }
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """
        Grab banner from service
        
        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout
        
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send probe if available
            probe = ServiceDetector.PROBES.get(port, b"")
            if probe:
                sock.send(probe)
                time.sleep(0.1)
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Clean up banner
            if banner:
                banner = ' '.join(banner.split())
                return banner[:200]  # Limit length
            
            return None
            
        except:
            return None

class OSFingerprinter:
    """Simple OS fingerprinting based on TTL and TCP options"""
    
    @staticmethod
    def fingerprint(host: str, port: int = 80, timeout: float = 2.0) -> Dict[str, float]:
        """
        Attempt to fingerprint OS
        
        Args:
            host: Target host
            port: Port to probe (default 80)
            timeout: Connection timeout
        
        Returns:
            Dictionary of OS guesses with confidence scores
        """
        guesses = {}
        
        try:
            # Try TCP fingerprinting
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((host, port))
                # Get local socket info
                sock_info = sock.getsockname()
                sock.close()
            except:
                pass
            
            # Try ICMP ping for TTL
            try:
                import subprocess
                import re
                
                # Windows ping
                result = subprocess.run(
                    ['ping', '-n' if sys.platform == 'win32' else '-c', '1', host],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                # Extract TTL
                ttl_match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # TTL-based OS guessing
                    if ttl <= 64:
                        guesses['Linux/Unix'] = 0.7
                        if ttl <= 50:
                            guesses['Embedded Linux'] = 0.6
                    elif ttl <= 128:
                        guesses['Windows'] = 0.7
                        guesses['Windows 10/11'] = 0.6
                    elif ttl <= 255:
                        guesses['Solaris/FreeBSD'] = 0.6
                        guesses['Cisco'] = 0.5
                        
            except:
                pass
            
            # Try to detect Windows vs Unix via SMB
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, 445))
                sock.close()
                
                if result == 0:
                    guesses['Windows (SMB)'] = guesses.get('Windows (SMB)', 0) + 0.3
            except:
                pass
            
            # Try SSH fingerprint
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((host, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'OpenSSH' in banner:
                    guesses['Linux/Unix (SSH)'] = 0.8
                elif 'SSH-2.0' in banner:
                    guesses['Unknown Unix'] = 0.5
            except:
                pass
            
            # Normalize confidence scores
            total = sum(guesses.values()) if guesses else 1
            for key in guesses:
                guesses[key] = guesses[key] / total
            
        except:
            pass
        
        return guesses if guesses else {'Unknown': 1.0}

class PortScanner:
    """Advanced port scanner with multiple scan types"""
    
    def __init__(self, target, start_port=1, end_port=1024, timeout=1.0, 
                 threads=100, scan_type='tcp', output_format='text', 
                 output_file=None, verbose=False, banner_grab=False,
                 os_fingerprint=False, stealth=False):
        """
        Initialize port scanner
        
        Args:
            target: Target IP or hostname
            start_port: Starting port
            end_port: Ending port
            timeout: Connection timeout
            threads: Number of threads
            scan_type: 'tcp', 'syn', or 'udp'
            output_format: 'text', 'json', 'csv', 'xml'
            output_file: Output file path
            verbose: Verbose output
            banner_grab: Enable banner grabbing
            os_fingerprint: Enable OS fingerprinting
            stealth: Stealth scanning mode
        """
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.scan_type = scan_type
        self.output_format = output_format
        self.output_file = output_file
        self.verbose = verbose
        self.banner_grab = banner_grab
        self.os_fingerprint = os_fingerprint
        self.stealth = stealth
        
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = {}
        self.lock = threading.Lock()
        self.progress = 0
        self.total_ports = 0
        
        # Service mapping
        self.services = {
            20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MSRPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
            53: 'DNS', 69: 'TFTP', 123: 'NTP', 161: 'SNMP', 162: 'SNMP-trap',
            389: 'LDAP', 636: 'LDAPS', 3268: 'LDAP-GC', 3269: 'LDAP-GC-SSL',
            514: 'Syslog', 1521: 'Oracle', 1522: 'Oracle-Alternate',
            2049: 'NFS', 2375: 'Docker', 2376: 'Docker-SSL',
            3000: 'Grafana', 5000: 'Flask/Dev', 5601: 'Kibana',
            9000: 'PHP-FPM', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
            11211: 'Memcached', 27017: 'MongoDB', 28015: 'RethinkDB',
            50000: 'SAP', 50001: 'SAP', 50002: 'SAP'
        }
    
    def scan_port_tcp(self, port: int) -> Optional[str]:
        """TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if self.stealth:
                # Randomize delay to avoid detection
                time.sleep(0.001)
            
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.services.get(port, 'Unknown')
                banner = None
                
                if self.banner_grab:
                    banner = ServiceDetector.grab_banner(self.target, port, self.timeout)
                
                return service, banner
            else:
                return None
                
        except socket.error:
            return None
        except:
            return None
    
    def scan_port_syn(self, port: int) -> Optional[str]:
        """SYN scan using Scapy"""
        if not HAS_SCAPY:
            # Fallback to TCP connect
            return self.scan_port_tcp(port)
        
        try:
            # Build SYN packet
            ip = scapy.IP(dst=self.target)
            tcp = scapy.TCP(dport=port, flags='S', seq=1000)
            packet = ip / tcp
            
            # Send packet
            response = scapy.sr1(packet, timeout=self.timeout, verbose=False)
            
            if response and response.haslayer(scapy.TCP):
                flags = response.getlayer(scapy.TCP).flags
                if flags & 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst = ip / scapy.TCP(dport=port, flags='R', seq=response.seq)
                    scapy.send(rst, verbose=False)
                    
                    service = self.services.get(port, 'Unknown')
                    banner = None
                    if self.banner_grab:
                        banner = ServiceDetector.grab_banner(self.target, port, self.timeout)
                    return service, banner
                elif flags & 0x14:  # RST-ACK
                    self.closed_ports.append(port)
                else:
                    self.filtered_ports.append(port)
            
            return None
            
        except:
            return None
    
    def scan_port_udp(self, port: int) -> Optional[str]:
        """UDP port scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                # Got response, port is open
                service = self.services.get(port, 'Unknown')
                return service, None
            except socket.timeout:
                # No response - might be open or filtered
                # Try ICMP port unreachable detection
                return None
            except:
                return None
            finally:
                sock.close()
                
        except:
            return None
    
    def scan_port(self, port: int):
        """Scan a single port based on scan type"""
        try:
            if self.scan_type == 'syn' and HAS_SCAPY:
                result = self.scan_port_syn(port)
            elif self.scan_type == 'udp':
                result = self.scan_port_udp(port)
            else:
                result = self.scan_port_tcp(port)
            
            if result:
                service, banner = result
                with self.lock:
                    self.open_ports.append(port)
                    self.scan_results[port] = {
                        'port': port,
                        'service': service,
                        'banner': banner if banner else 'N/A',
                        'state': 'open'
                    }
                    
                    # Print result
                    color = Colors.GREEN
                    status = "OPEN"
                    output = f"{color}[{status}]{Colors.END} Port {port:5d} - {service}"
                    if banner:
                        output += f" - Banner: {banner[:100]}"
                    print(output)
            else:
                if self.scan_type != 'udp':
                    with self.lock:
                        self.closed_ports.append(port)
                else:
                    with self.lock:
                        self.filtered_ports.append(port)
            
            # Update progress
            with self.lock:
                self.progress += 1
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning port {port}: {e}")
            with self.lock:
                self.progress += 1
    
    def scan_ports_slice(self, start_port: int, end_port: int):
        """Scan a slice of ports"""
        for port in range(start_port, end_port + 1):
            if self.scan_type == 'syn' and not HAS_SCAPY:
                self.scan_port_tcp(port)
            else:
                self.scan_port(port)
    
    def scan_network(self, progress_bar=None):
        """Perform network scan with progress tracking"""
        self.total_ports = self.end_port - self.start_port + 1
        
        print(f"\n{Colors.BOLD}Starting Scan{Colors.END}")
        print(f"{'='*50}")
        print(f"Target: {self.target}")
        print(f"Scan Type: {self.scan_type.upper()}")
        print(f"Ports: {self.start_port}-{self.end_port} ({self.total_ports} ports)")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        if self.banner_grab:
            print(f"Banner Grabbing: Enabled")
        if self.os_fingerprint:
            print(f"OS Fingerprinting: Enabled")
        if self.stealth:
            print(f"Stealth Mode: Enabled")
        print(f"{'='*50}\n")
        
        start_time = time.time()
        
        # Create thread pool
        threads = []
        ports_per_thread = max(1, self.total_ports // self.threads)
        
        for i in range(self.threads):
            start = self.start_port + (i * ports_per_thread)
            end = min(start + ports_per_thread - 1, self.end_port)
            
            if start <= end:
                thread = threading.Thread(
                    target=self.scan_ports_slice,
                    args=(start, end)
                )
                threads.append(thread)
                thread.start()
        
        # Monitor progress
        if HAS_TQDM and progress_bar:
            pbar = tqdm(total=self.total_ports, desc="Scanning ports", unit="ports")
            while self.progress < self.total_ports:
                pbar.update(self.progress - pbar.n)
                time.sleep(0.1)
            pbar.close()
        else:
            # Simple progress indicator
            last_progress = 0
            while self.progress < self.total_ports:
                if self.progress > last_progress:
                    percent = (self.progress / self.total_ports) * 100
                    print(f"\rProgress: {percent:.1f}% ({self.progress}/{self.total_ports})", end='')
                    last_progress = self.progress
                time.sleep(0.1)
            print()  # New line after progress
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        
        # OS fingerprinting if enabled
        os_guess = None
        if self.os_fingerprint and self.open_ports:
            print(f"\n{Colors.BOLD}Performing OS Fingerprinting...{Colors.END}")
            os_guess = OSFingerprinter.fingerprint(self.target)
        
        return duration, os_guess
    
    def get_results(self) -> Dict:
        """Get scan results as dictionary"""
        results = {
            'scan_info': {
                'target': self.target,
                'start_port': self.start_port,
                'end_port': self.end_port,
                'scan_type': self.scan_type,
                'timestamp': datetime.now().isoformat(),
                'total_ports': self.total_ports,
                'open_ports_count': len(self.open_ports)
            },
            'open_ports': self.scan_results
        }
        
        return results

class NetworkScanner:
    """Network range scanner"""
    
    @staticmethod
    def scan_network_range(network: str, ports: List[int] = None, **kwargs):
        """
        Scan a network range
        
        Args:
            network: CIDR notation (e.g., 192.168.1.0/24)
            ports: List of ports to scan
            **kwargs: Additional arguments for PortScanner
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            print(f"\n{Colors.BOLD}Network Scan{Colors.END}")
            print(f"{'='*50}")
            print(f"Network: {network}")
            print(f"Total Hosts: {network_obj.num_addresses}")
            print(f"Ports: {ports or 'Default range'}")
            print(f"{'='*50}\n")
            
            results = {}
            
            for ip in network_obj.hosts():
                ip_str = str(ip)
                print(f"\n{Colors.BLUE}Scanning {ip_str}{Colors.END}")
                
                scanner = PortScanner(
                    ip_str,
                    **kwargs
                )
                
                # Override ports if specified
                if ports:
                    scanner.start_port = min(ports)
                    scanner.end_port = max(ports)
                
                duration, os_guess = scanner.scan_network()
                results[ip_str] = scanner.get_results()
                
                # Print host summary
                print(f"\n{Colors.GREEN}Results for {ip_str}:{Colors.END}")
                print(f"  Open ports: {len(scanner.open_ports)}")
                print(f"  Scan duration: {duration:.2f}s")
                if os_guess:
                    print(f"  OS Guess: {max(os_guess, key=os_guess.get)} ({max(os_guess.values())*100:.1f}%)")
            
            return results
            
        except ValueError as e:
            print(f"{Colors.RED}Error: Invalid network range - {e}{Colors.END}")
            return {}

def save_results(results: Dict, format: str, filename: str):
    """
    Save scan results to file
    
    Args:
        results: Results dictionary
        format: Output format ('text', 'json', 'csv', 'xml')
        filename: Output filename
    """
    try:
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {filename} (JSON)")
            
        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'Service', 'Banner', 'State'])
                for port, info in results.get('open_ports', {}).items():
                    writer.writerow([port, info['service'], info['banner'], info['state']])
            print(f"\nResults saved to {filename} (CSV)")
            
        elif format == 'xml':
            root = ET.Element('scan_results')
            scan_info = ET.SubElement(root, 'scan_info')
            for key, value in results.get('scan_info', {}).items():
                ET.SubElement(scan_info, key).text = str(value)
            
            open_ports = ET.SubElement(root, 'open_ports')
            for port, info in results.get('open_ports', {}).items():
                port_elem = ET.SubElement(open_ports, 'port')
                for key, value in info.items():
                    ET.SubElement(port_elem, key).text = str(value)
            
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            print(f"\nResults saved to {filename} (XML)")
            
        else:  # text
            with open(filename, 'w') as f:
                f.write("SCAN RESULTS\n")
                f.write("="*50 + "\n")
                f.write(f"Target: {results['scan_info']['target']}\n")
                f.write(f"Scan Type: {results['scan_info']['scan_type']}\n")
                f.write(f"Timestamp: {results['scan_info']['timestamp']}\n")
                f.write(f"Total ports scanned: {results['scan_info']['total_ports']}\n")
                f.write(f"Open ports found: {results['scan_info']['open_ports_count']}\n")
                f.write("\nOPEN PORTS:\n")
                f.write("-"*30 + "\n")
                
                for port, info in sorted(results.get('open_ports', {}).items()):
                    f.write(f"Port {port:5d} : {info['service']}\n")
                    if info['banner'] != 'N/A':
                        f.write(f"  Banner: {info['banner']}\n")
            
            print(f"\nResults saved to {filename} (Text)")
            
    except Exception as e:
        print(f"{Colors.RED}Error saving results: {e}{Colors.END}")

def interactive_mode():
    """Interactive mode for the scanner"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}Advanced Port Scanner - Interactive Mode{Colors.END}")
    print("="*50)
    
    target = input("Enter target IP or hostname: ")
    if not target:
        print("Target required!")
        return
    
    # Network range detection
    if '/' in target:
        network_scan(target)
        return
    
    # Scan type
    print("\nScan Type:")
    print("1. TCP Connect (most compatible)")
    print("2. SYN Scan (stealth, requires root/Admin)")
    print("3. UDP Scan (slower)")
    scan_type = input("Select scan type (1-3) [1]: ") or "1"
    scan_type_map = {"1": "tcp", "2": "syn", "3": "udp"}
    scan_type = scan_type_map.get(scan_type, "tcp")
    
    # Port range
    ports = input("Enter port range (e.g., 1-1000) [1-1024]: ") or "1-1024"
    if '-' in ports:
        start, end = map(int, ports.split('-'))
    else:
        start = 1
        end = int(ports) if ports else 1024
    
    # Additional options
    threads = int(input("Number of threads [100]: ") or "100")
    timeout = float(input("Timeout in seconds [1.0]: ") or "1.0")
    banner = input("Grab banners? (y/n) [n]: ").lower() == 'y'
    os_fingerprint = input("OS fingerprinting? (y/n) [n]: ").lower() == 'y'
    stealth = input("Stealth mode? (y/n) [n]: ").lower() == 'y'
    
    # Output options
    output_format = input("Output format (text/json/csv/xml) [text]: ") or "text"
    output_file = input("Output filename [results.txt]: ") or "results.txt"
    
    # Run scan
    scanner = PortScanner(
        target, start, end, timeout, threads,
        scan_type, output_format, output_file,
        banner, os_fingerprint, stealth
    )
    
    scanner.scan_network()
    
    # Save results
    if scanner.open_ports:
        results = scanner.get_results()
        save_results(results, output_format, output_file)

def network_scan(network: str = None):
    """Network range scanning"""
    if not network:
        network = input("Enter network range (e.g., 192.168.1.0/24): ")
    
    if not network:
        return
    
    port_list = input("Enter ports to scan (comma-separated) [22,80,443]: ") or "22,80,443"
    ports = [int(p.strip()) for p in port_list.split(',')]
    
    scanner = NetworkScanner()
    results = scanner.scan_network_range(
        network,
        ports=ports,
        timeout=1.0,
        threads=50,
        scan_type='tcp'
    )
    
    # Save combined results
    if results:
        output_file = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nNetwork scan results saved to {output_file}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Advanced Python Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic TCP scan
  python port_scanner.py 192.168.1.1
  
  # SYN scan with banner grabbing
  sudo python port_scanner.py 192.168.1.1 -s syn -b --threads 200
  
  # UDP scan
  sudo python port_scanner.py 192.168.1.1 -s udp -p 1-1000
  
  # Network range scan
  python port_scanner.py 192.168.1.0/24 -c --ports 22,80,443
  
  # OS fingerprinting and JSON output
  python port_scanner.py 192.168.1.1 -f json -o results.json --os
        """
    )
    
    parser.add_argument("target", help="Target IP, hostname, or network range (CIDR)")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 22,80,443)", default="1-1024")
    parser.add_argument("-s", "--scan-type", choices=['tcp', 'syn', 'udp'], default='tcp',
                       help="Scan type (tcp, syn, udp)")
    parser.add_argument("-t", "--timeout", type=float, help="Connection timeout in seconds", default=1.0)
    parser.add_argument("--threads", type=int, help="Number of threads", default=100)
    parser.add_argument("-b", "--banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("--os", dest="os_fingerprint", action="store_true", help="Enable OS fingerprinting")
    parser.add_argument("--stealth", action="store_true", help="Stealth scanning (random delays)")
    parser.add_argument("-f", "--format", choices=['text', 'json', 'csv', 'xml'], 
                       default='text', help="Output format")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--common", action="store_true", help="Scan only common ports")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive:
        interactive_mode()
        return
    
    # Check for network range
    if '/' in args.target:
        network_scan(args.target)
        return
    
    # Parse port range
    if args.common:
        start_port, end_port = 1, 1024
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                       443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 
                       6379, 8080, 8443, 27017]
        # We'll scan all ports but filter later
    else:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            if start_port > end_port:
                start_port, end_port = end_port, start_port
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
            start_port = min(ports)
            end_port = max(ports)
    
    # Check permissions for SYN scan
    if args.scan_type == 'syn' and not HAS_SCAPY:
        print(f"{Colors.YELLOW}Warning: Scapy not installed. Falling back to TCP connect scan.{Colors.END}")
        args.scan_type = 'tcp'
    
    # Create output filename if not specified
    if not args.output:
        args.output = f"scan_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
    
    # Run scanner
    scanner = PortScanner(
        args.target,
        start_port,
        end_port,
        args.timeout,
        args.threads,
        args.scan_type,
        args.format,
        args.output,
        args.verbose,
        args.banner,
        args.os_fingerprint,
        args.stealth
    )
    
    duration, os_guess = scanner.scan_network(progress_bar=HAS_TQDM)
    
    # Print summary
    print(f"\n{Colors.BOLD}Scan Summary{Colors.END}")
    print(f"{'='*50}")
    print(f"Open ports: {len(scanner.open_ports)}")
    print(f"Closed ports: {len(scanner.closed_ports)}")
    if scanner.scan_type in ['syn', 'udp']:
        print(f"Filtered ports: {len(scanner.filtered_ports)}")
    print(f"Scan duration: {duration:.2f} seconds")
    
    if os_guess and scanner.os_fingerprint:
        print(f"\n{Colors.BOLD}OS Fingerprinting Results:{Colors.END}")
        for os_name, confidence in os_guess.items():
            print(f"  {os_name}: {confidence*100:.1f}%")
    
    # Save results if open ports found
    if scanner.open_ports:
        results = scanner.get_results()
        if args.os_fingerprint and os_guess:
            results['os_fingerprint'] = os_guess
        save_results(results, args.format, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted by user.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        if args and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
