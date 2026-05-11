#------------------------
# IMPORTED LIBRARY NEED
#------------------------

import sys           # Get Python version and command-line arguments
import socket        # Get hostname and IP address
import threading     # Get multiple port scans at the same time (faster than Single-threaded execution)
from scanners.scanner import Scanner
from utils.logger import log_message
from utils.report import save_report

#------------------------
# PORT_SERVICE_MAP
#------------------------

# This dictionary identify the well-known port by their numbers of services
# In real life service can run on any ports
# These are all the common ports and services :

PORT_SERVICE_MAP = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP",
    135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "Syslog",
    587: "SMTP Submission", 631: "IPP Printing", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP Proxy", 8443: "HTTPS-Alt"
}

class PortScanner(Scanner):
    def __init__(self, target, start_port=None, end_port=None):
        super().__init__(target)
        self.start_port = start_port
        self.end_port = (end_port)
        self.results = []
    #------------------------
    # FUNCTION : scan_port
    #------------------------

    # This function checks one port on the target
    # This function run in the thread

    def scan_port(self, target, port, results):
        try:

            # Create an INET, STREAMing socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Timeout 0.5 second so it won't scan forever
            sock.settimeout(0.5)

            # Try to connect to the target on the given port
            # Connect_ex returns 0 if the connection is successful
            result = sock.connect_ex((target, port))

            # IF result == 0 , The port is open
            if result == 0:

                # Get service name from dictionary (if known)
                service = PORT_SERVICE_MAP.get(port, "Unknown Service")

                # Store open port and service name
                results.append((port, service))

            # Always close the socket
            sock.close()
        except:
            # Ignore any errors like : connection or permission error
            pass

    #------------------------
    # FUNCTION : scan_port
    #------------------------

    # This function manages threads and scans multiple ports

    def run_scanner(self, target, ports):
        threads = [] # Store the thread objects
        #results = [] # Store the oprn ports

        # Create a thread for each port
        for port in ports:

            # The thread function will run
            t = threading.Thread(target=self.scan_port, 
            
            # Arguments will passed to the function
            args=(self.target, port, self.results))

            # Start the thread
            t.start()
            threads.append(t)

        # Wait for all threads to finish
        for t in threads:
            t.join()

        # Print the Scanning completed 
        print("Scanning completed....")
    

    # -----------------------
    # FUNCTION: scan_common_ports
    # -----------------------

    # Scans ports 1–1023 (well-known ports)

    def scan_common_ports(self):
        self.run_scanner(self.target, range(1, 1024))

    # -----------------------
    # FUNCTION: scan_custom_range
    # -----------------------

    # Scans what's range of port the user want to scan

    def scan_custom_range(self):

        # If ports are provided via command line
        if self.start_port and self.end_port:
            start = int(self.start_port)
            end = int(self.end_port)
            self.run_scanner(self.target, range(start, end + 1))
            
            return
        
        # Ask the user to input their desired range 
        try:
            start = int(input("Enter start port: "))
            end = int(input("Enter end port: "))  

            # Validate port range
            # IF start < 1 ex: -5 (Invalid)
            # IF end > 65535 ex: 70000 (Invalid)
            # IF start > end ex: start 100 and end 50 (Invalid)
            if start < 1 or end > 65535 or start > end:
                print("Invalid port range.")
                return

            self.run_scanner(self.target, range(start, end + 1))

        except ValueError:

            # If user input non-numbers
            print("Please enter valid numbers.")

    # ----------------------
    # FUNCTION: menu_mode
    # ----------------------
    # Interactive menu when no CLI arguments are used

    def scan(self):
        log_message(f"PortScanner: start scanning {self.target}")
        
        print("\nSelect scan mode:")
        print("1. Common ports (1–1023)")
        print("2. Custom port range")
        choice = input("\nEnter choice (1/2): ")

        if choice == "1":
            self.scan_common_ports()
        elif choice == "2":
            self.scan_custom_range()
        else:
            print("Invalid selection.")
            
        results = {
            "type": "port",
            "target": self.target,
            "open_ports": self.results
        }
        
        # Print results
        if not self.results:
            print("\nNo open ports found.")
        else:
            print("\nOpen ports:")
            for port, service in sorted(self.results):
                print(f"- {port} ({service})")

        save_report("port_scan", self.results)
        log_message(f"PortScanner completed for {self.target}")

        return results


# -----------------------
# FUNCTION: cli_mode
# -----------------------
# Handles command-line usage

def cli_mode(argv):

    # Check for minimum required arguments
    if len(argv) < 3:
        print("Usage:")
        print("  python3 script.py <target> common")
        print("  python3 script.py <target> range <start> <end>")
        return

    target = argv[1] # Hostname / IP of the target
    mode = argv[2]   # Scan mode

    if mode == "common":
        scanner = PortScanner(target, 1, 1023)
        scanner.scan()
        
    elif mode == "range":
        if len(argv) != 5:
            print("Usage: python3 script.py <target> range <start> <end>")
            return
        scanner = PortScanner(target, argv[3], argv[4])
        scanner.scan()

    else:
        print("Unknown mode. Use 'common' or 'range'.")

# ----------------------------
# PROGRAM ENTRY POINT
# ----------------------------
# This block runs only if the script is executed directly
def Run_PortScanner():
    # If command-line arguments exist → CLI mode
    if len(sys.argv) > 1:
        cli_mode(sys.argv)

    # Otherwise → interactive mode
    else:
        target = input("Enter target IP or hostname: ")

        # Convert hostname to IP address
        target = socket.gethostbyname(target)
        scanner = PortScanner(target)
        scanner.scan()

if __name__ == "__main__":
    Run_PortScanner()
    