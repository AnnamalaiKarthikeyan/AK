import socket
import platform
import subprocess

# Sample vulnerability database (you can expand this!)
vulnerability_db = {
    "Apache/2.4.49": "CVE-2021-41773 - Path Traversal",
    "OpenSSH_7.2p2": "CVE-2016-0777 - Information Disclosure",
    "nginx/1.12.0": "CVE-2017-7529 - Integer Overflow",
}

# Scan localhost ports and check banners
def scan_localhost_ports(start_port=1, end_port=1024):
    print("[*] Scanning localhost for open ports and vulnerable services...\n")
    ip = "127.0.0.1"
    for port in range(start_port, end_port):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode().strip()
            except:
                banner = "Unknown"
            print(f"[+] Port {port} open - Banner: {banner}")
            check_vulnerability(banner)
            s.close()
        except:
            pass

# Check if banner matches a known vulnerability
def check_vulnerability(banner):
    for signature in vulnerability_db:
        if signature in banner:
            print(f"  [!] Vulnerability Found: {vulnerability_db[signature]}")

# Optional: Show system info
def get_system_info():
    print("\n[*] Basic System Info")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Processor: {platform.processor()}")
    print(f"  Python Version: {platform.python_version()}")
    print("-" * 40)

# Optional: List running services (Linux only)
def list_services():
    if platform.system() == "Linux":
        print("\n[*] Listing running services...")
        try:
            output = subprocess.check_output("systemctl --type=service --state=running", shell=True)
            print(output.decode())
        except Exception as e:
            print(f"Error getting services: {e}")
    else:
        print("\n[!] Service listing is only supported on Linux for now.")

# Run all functions
if __name__ == "__main__":
    get_system_info()
    scan_localhost_ports(1, 1024)  # You can increase the range
    list_services()
