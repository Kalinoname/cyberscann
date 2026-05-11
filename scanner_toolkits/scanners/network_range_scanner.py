import socket
import threading
import time
from scanners.scanner import Scanner # Module from the Base Class Scanner
from utils.logger import log_message  # Logging history, from module logger.py
from utils.report import save_report  # Save report, from module report.py

class NetworkRangeScanner(Scanner):
    def __init__(self, base_network: str, start_host: int, end_host: int, timeout: float = 0.5):
        
        target = f"{base_network}.{start_host}-{end_host}" # IP base for targets, ex: 192.168.1.1-254
        super().__init__(target) # Call the constructor of the Base Class Scanner, so it will get the target from there
        
        self.base_network = base_network
        self.start_host = start_host
        self.end_host = end_host
        self.timeout = timeout
        self.common_ports = [21, 22, 23, 25, 53, 
                             80, 110, 143, 443, 
                             3306, 3389, 8080] # Some common ports, since we scan a range of networks we shouldn't specific it
                    
    def scan_single_ip(self, ip):
        open_ports = []
        
        # Create a thread for each port
        for port in self.common_ports:
           # TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                # It returns 0 if the connection is succeed
                if sock.connect_ex((ip, port)) == 0: # equal to 0 means that port is open, if not it's close
                    open_ports.append(port)
            except:
                pass # To ignore error
            finally:
                    # To close socket safely
                try:
                    sock.close()
                except Exception: # Prevent error that occurs when closing socket
                    pass
            
        return open_ports
    
    # Main scan
    def scan(self):
        # Show log message
        log_message(f"NetworkRangeScanner: start {self.base_network}.{self.start_host}-{self.end_host}")

        print(f"\nNetworkRangeScanner: scanning {self.base_network}.{self.start_host} - {self.base_network}.{self.end_host}")

        active_devices = {} # Dictionary to store a device with their open ports accordingly, ex: {"192.168.1.1" : [7, 20, 80]}
        start_time = time.time() # Use for recording the duration of the process
        threads = []
        
        lock = threading.Lock()
        
        # Nested function
        def scan_ip(host):
            ip = f"{self.base_network}.{host}" # Base Network given by user, 192.168.1 then it'll loop each hosts
            
            ports = self.scan_single_ip(ip)
            
            if ports:
                with lock:
                    active_devices[ip] = ports
                print(f"{ip} ACTIVE - {ports}")
                
        # A loop for hosts from start to the end with threading, a thread for each target
        for host in range(self.start_host, self.end_host + 1):
            thread = threading.Thread(target = scan_ip, args = (host,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()            
                
        # Calculate the duration took for a scan
        duration = round(time.time() - start_time, 2)
        
        # Results for the report, which implemented from Base Class
        self.results = {
            "scan_type": "network_range_scan", # Type of scan
            "base_network": self.base_network, # Show base network
            "range": f"{self.start_host}-{self.end_host}", # Show start to end hosts
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), # Date and time of the scan in YY/MM/DD H/M/S format
            "duration_seconds": duration, # Show duration
            "active_devices": active_devices # Show active devices
        }
        
        save_report("network_range_scan", self.results)
        
        log_message(f"NetworkRangeScanner: completed found = {len(active_devices)}")

        # Tell the user that the scan is completed and showcasing the active devices on the network
        print(f"Network range scan complete! Active devices found: {len(active_devices)}")
        print(f"Completed in {duration} seconds")