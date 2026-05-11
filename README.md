* Project Overview

# BeydaScanner - ScannerToolkits #
Developed by: Python in Cybersecurity - Team 6
 *** Team 6 Members include: 
    @Oeun Vanmonireak 
    @Hean Chhanun
    @Rous Sovann Makara

Beyda Scanner is final python project. It's a Python-based multi-scanner toolkit which includes 3 main features:

- Port Scanning by @Rous Sovann Makara
- Network Range Scanning by @Oeun Vanmonireak
- Web Scanning by @Hean Chhanun

The name "Beyda" inspires from "3" as in Khmer it's pronounced as "Bey", which represent the 3 main scanners of this project.

There are also 2 smaller features which are:
    - Reporting
    - Logging

These 3 scanners follow a Base Class "Scanner" that allows clean structure, consistency and controlled work flow as well as following the concept of OOP in Python.

---

# Features Description:

### Port Scanner
    - A scanner that provides port scanning services where the users will have 2 options to choose from:
            *** Well-Known Port Scanning (1-1023)
            *** Customed Range Port Scanning (User can scan any range as they wish)
    - Fast thread scanning
    - Check an open port and report the known services from service map
    - Logging and report saving of each scans

### Network Range Scanner
    - This is an IP/Network scanner where you can scan a specific range or whole range of hosts on a subnet depend on how you like. It requires the users to enter a base network (example: 192.168.1) then enter start host and end host to scan.
    - Uses threading for faster scanning
    - Show lives results
    - Logging and report saving of each scans

### Web Scanner
    - It's a scanner that scans. detects and analyzes:
        - Missing security headers in website
        - Server Header
        - Reflected XSS
    - Colored Output
    - Logging and report saving of each scans

* Project Structure 

|---scanner_toolkits/
|---main.py
|---scanners/
|-------scanner.py                  # Base Class
|-------port_scanner.py             # Port Scanner
|-------network_range_scanner.py    # Network Ranger Scanner
|-------web_scanner.py              # Web Scanner
|-------utils/
|-------logger.py
|-------report.py
|---logs/       # Logs history
|---reports/    # Save scan reports
|---README.md
|---requirements.txt

# Installation

Clone the project: 

- git clone https://github.com/Reakson/BeydaScanner.git
- cd BeydaScanner

Install modules packet:
- pip install -r requirements.txt

Run the program:
- python main.py

# Usage

From the main program: 
---
Select scan type:
1) Port Scanner
2) Network Range Scanner
3) Web Scanner
4) Exit
---

# Logs and Reports
Every scan generates a log and report.
- Log: Shows date and time as well as the details of what type of scan and info.
- Report: Saves every scans and shows specific details.

# Legal Disclaimer
---
This toolkit is mainly developed for our project and is aim for educational and authorized security testing purposes only, where we can further use it for our study in Cybersecurity.

DISCLAIMER: Do NOT scan systems or environments that you do not own or have permission to test!
----
# Contributors:
As mentioned above, our team consists of 3 members:
    @Oeun Vanmonireak 
    @Hean Chhanun
    @Rous Sovann Makara

We also would love to say thanks and show our appreciations to our lecturer of this course Mr. Han Leangsiv for providing us with crucial knowlegdes, beneficial advices and continuous supports.

We were able to build this project solely based on what we've learnt from our lecturer during this term and a lot of researching on our own.
---

All Rights Reserved - Python in Cybersecurity Team 6
CADT - IDT
Department of Telecommunications and Networking Specialized in Cybersecurity
Year 2 - 2025-2026