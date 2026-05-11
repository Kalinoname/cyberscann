import os
import json
import time

def save_report(scan_type, data):
    os.makedirs("reports", exist_ok = True)
    filename = f"reports/{scan_type}_{int(time.time())}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent = 4)

    return filename
