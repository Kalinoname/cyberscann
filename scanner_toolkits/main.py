import socket
from scanners.network_range_scanner import NetworkRangeScanner
from scanners.port_scanner import PortScanner
from scanners.port_scanner import Run_PortScanner
from scanners.web_scanner import WebScanner
from scanners.web_scanner import Run_WebScanner


def resolve_host(target):
    # Convert hostname to IP safely.
    try:
        return socket.gethostbyname(target)
    except:
        return target  # if it's already an IP


def network_range():
    # Ask user for network range input.
    base = input("Base network (e.g., 192.168.1): ").strip()
    start = int(input("Start host: "))
    end = int(input("End host: "))
    return base, start, end


def main():
    BANNER = """
    ██████╗ ███████╗██╗   ██╗██████╗  █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
    ██╔══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██████╔╝█████╗   ╚████╔╝ ██║  ██║███████║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔══██╗██╔══╝    ╚██╔╝  ██║  ██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██████╔╝███████╗   ██║   ██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        BeydaScanner | ScannerToolkits
        Developed by: Python in Cybersecurity Team 6
    """
    print(BANNER)
    
    while (True):
        print("\nSelect scan type:")
        print("1) Port Scanner")
        print("2) Network Range Scanner")
        print("3) Web Scanner")
        print("4) Exit")

        choice = input("> ").strip()

        # # 1. Port Scanner
        if choice == "1":
            Run_PortScanner()
        
        # # 2. Network Range Scanner
        elif choice == "2":
            base, start, end = network_range()
            scanner = NetworkRangeScanner(base, start, end)
            scanner.scan()
            
        # # 3. Web Scanner
        elif choice == "3":
            Run_WebScanner()
        
        elif choice == "4":
                print("Exiting BeydaScanner. Goodbye!")
                break
        else:
            print("Invalid choice. Try again with valid choice (1-4)")

if __name__ == "__main__":
    main()
