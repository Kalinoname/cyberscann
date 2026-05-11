import os
import time

LOG_FILE = "logs/scan.log"

def log_message(msg):
    os.makedirs("logs", exist_ok = True)
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {msg}\n")
