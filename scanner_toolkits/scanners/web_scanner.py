import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from requests.exceptions import RequestException
from scanners.scanner import Scanner
from utils.logger import log_message
from utils.report import save_report

class WebScanner(Scanner):
    # COMMON_PATHS is a list of risky places on a website that should NOT be open.
    common_paths =  [
        "/.git/", "/server-status", "/backup/", "/admin/", "/config/", "/test/"
    ] 


    # XSS_PAYLOADS = test attacks used to see if the website is vulnerable.
    xss_paloads =  [
    "vscan_test_reflect_12345",
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=\"javascript:window.onerror=alert; throw XSS\">",
    "<video><source onerror=\"javascript:alert(\\\"XSS\\\")\"></video>",
    "<input value=\"XSS\" type=\"text\">",
    "<applet code=\"javascript:confirm(document.cookie);\"></applet>",
    "<isindex x=\"javascript:\" onmouseover=\"alert(XSS)\">",
    "\"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "\"><img src=\"x:x\" onerror=\"alert(XSS)\">",
    "\"><iframe src=\"javascript:alert(XSS)\">",
    "<object data=\"javascript:alert(XSS)\"></object>",
    "<isindex type=image src=1 onerror=alert(XSS)>",
    "<img src=x:alert(alt) onerror=eval(src) alt=0>",
    "<img src=\"x:gif\" onerror=\"window\"></img>",
    "<iframe/src=\"data:text/html,<svg onload=alert(1)>\">",
    "<meta content=\"&#10; 1 &#10;; JAVASCRIPT: alert(1)\" http-equiv=\"refresh\">",
    "<svg><script xlink:href=data:,window.open(\\\"https://www.google.com/\\\")></script>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:confirm(1)\">",
    "<iframe src=javascript:alert(document.location)>",
    "<form><a href=\"javascript:\\u0061lert(1)\">X</a></form>",
    "</script><img/*%00/src=\"worksinchrome:prompt(1)\"/%00*/onerror=\"eval(src)\">",
    "<style>//*{x:expression(alert(/xss/))}//<style></style>"                   
    ]



    def __init__(self, target: str, timeout = 5):
        super().__init__(target)
        self.timeout = timeout



    def build_xss_urls(self):

        parsed = urlparse(self.target)  # I use it to understand the structure of the URL.
        query = parse_qs(parsed.query) # I use it to extract URL parameters . like dictionary

        url = []

        # Target has NO parameters 
        if not query :
            for payload in self.xss_paloads:
                params = {"q": payload}
                xss_url = self.target + "?" + urlencode(params) # I use it to add value as a sting
                url.append(xss_url)

            return url
        
        # Target HAS parameters → replace each parameter with payloads
        for param in query.keys():
            for payload in self.xss_paloads:
                new_query = query.copy()
                new_query[param] = payload  # I use it to replace the current parameter with an XSS payload.

                encoded_q = urlencode(new_query, doseq=True) # I use it to Converts dictionary → URL string
                new_url = urlunparse((parsed.scheme, 
                                      parsed.netloc,
                                      parsed.path,
                                      "",
                                      encoded_q,
                                      ""))                   #  I use it to rebuild url 
                url.append(new_url)
            
        return url
        
    
    def scan(self):
        
        log_message(f"WebScanner: start {self.target}")
        print(f"\nWeb Scanner scanning - {self.target}")
        results = {
            "type": "web",
            "target": self.target,
            "vulnerability": []
        }


        # I do it to takes the HTTP headers from the website response.
        try:
            resp = requests.get(self.target, timeout = self.timeout, allow_redirects = True)
            headers = resp.headers

            # ----------------------
            # Check Server Header
            # ----------------------
            if "Server" in headers:
                server = headers["Server"]
                results["server"] = server

                if "Apache/2.2" in server or "Apache/2.0" in server:
                    results["vulnerability"].append({
                        "name": "Oldated Server",
                        "severity": "Medium",
                        "detail": f"Server report {server}. It is outdate server."
                    })

            # -------------------------------
            # Check Missing Security Headers
            # -------------------------------
            required_headers = [
                "Cache-Control",
                "Clear-Site-Data",
                "Content-Security-Policy",
                "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy",
                "Permissions-Policy",
                "Referrer-Policy",
                "Strict-Transport-Security",
                "X-Permitted-Cross-Domain-Policies",
                "X-DNS-Prefetch-Control",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
            ]

            missing = [h for h in required_headers if h not in headers]
            if missing:
                results["vulnerability"].append({
                    "name": "Missing Security Header",
                    "severity": "Low",
                    "detail": missing  
                })


            # -------------------------------
            # Check Common Paths
            # -------------------------------
            exposed_dirs = []
            for path in self.common_paths:
                try:
                    url = self.target.rstrip("/") + path # I use it to remove / end the url before and path
                    r = requests.get(url, timeout = 4) # I use it to Sends a GET request to check if the folder exists.

                    if r.status_code == 200 and ("Index of /" in r.text or path == "/.git/"):
                        exposed_dirs.append(url)
                except:
                    pass
            
            if exposed_dirs:
                results["vulnerability"].append({
                "name": "Exposed Directory",
                "severity": "Medium",
                "detail": exposed_dirs
                })
            
            # -------------------------------
            # Check XSS URL
            # -------------------------------
            xss_urls = self.build_xss_urls()
            xss_medium = []
            xss_high = []

            for test_url in xss_urls:
                try:
                    r = requests.get(test_url, timeout = 4)

                    for payload in self.xss_paloads:
                        if payload in r.text:
                            detail = f"Payload reflected: {payload} in URL {test_url}"
                            if "<script>" in payload.lower():
                                xss_high.append(detail)
                            else:
                                xss_medium.append(detail)
                
                except:
                    continue
            
            if xss_medium:
                results["vulnerability"].append({
                            "name": "Reflected XSS Detected",
                            "severity": "Medium",
                            "detail": xss_medium
                            })
            if xss_high:
                results["vulnerability"].append({
                            "name": "Reflected XSS Detected",
                            "severity": "High",
                            "detail": xss_high
                            })

        except RequestException:
            results["error"] = str(RequestException)
            results["vulnerability"].append({
                "name": "Target Unreachable",
                "severity": "Info",
                "detail": f"Could not reach target: {RequestException}"
            })
        
        save_report("web_scan", results)
        return results
    
# -------------------------
# Run_WebScanner
# -------------------------
def Run_WebScanner():
    print(f"\033[32m{"="*61}WebScanning{"="*61}\033[0m")
    print()

    url = True
    while url:
        target_url = input(f"\033[32mEnter target URL (ex.https://example.com)\033[0m :  ")
        valid_url = urlparse(target_url)

        if valid_url.scheme not in ["http", "https"]:
            print("Invalid URL! Please input a valid http/https link.")
        elif not valid_url.netloc:
            print("Invalid URL! Please input a valid http/https with (ex. ....example.com) link.")
        else:
            url = False

    scanner = WebScanner(target_url)
    results = scanner.scan()

    print()
    print(f"\033[32m{'=' * 60} Scan Results {'=' * 60}\033[0m")
    print()
    print(f"\033[34mTarget URL:\033[0m {target_url}")

    if "server" in results:
        print(f"\033[34mServer Header:\033[0m {results["server"]}")
        print()
    
    if "error" in results:
        print(f"\033[34mError\033[0m: {results["error"]}")
        print()
    

    print(f"\033[32mVulnerability found:\033[0m")
    if results["vulnerability"]:
        for v in results["vulnerability"]:
            print(f"\033[34m{v["name"]} \033[31m({v["severity"]})\033[0m:")
            if isinstance(v["detail"], list):
                for item in v["detail"]:
                    print(f"  - {item}")
            else:
                    print(f"  {v["detail"]}")

    else:
        print("\033[34mNo vulnerability detected.\033[0m")
    print(f"\033[32m{'=' * 134}\033[0m")
    print()

if __name__ == "__main__":
    Run_WebScanner()

#  code color output that i used in this (\033[32m for green, \033[31m for red, \033[34m for blue, \033[0m for reset color)

# -----------------------------------------------URL FOR TESTING ---------------------------------------------------------------

    # -------high, medium and low-------
        # https://postman-echo.com/get?x=<script>alert(1)</script>
        # https://postman-echo.com/get
        # https://postman-echo.com/get

    #-------medium and low--------------
        # https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://comodosslstore.com/resources/how-secure-is-https/%23:~:text%3DThe%2520reality%2520of%2520HTTPS%2520is,trusted%2520individual%2520runs%2520the%2520website.&ved=2ahUKEwjThbPQ-LmRAxXc1zgGHdcNJBEQFnoECFMQAw&usg=AOvVaw0-A97pVOxZJeNm6N44olGs

    # --------low----------------------
        # https://example.com

#  --------------------------------------------------END----------------------------------------------------------------------


# ----------------------------------------------------REFFERENCES--------------------------------------------------------------

    # https://docs.python.org/3/library/urllib.html library refference
    # https://owasp.org/www-project-secure-headers/ required_headers refference
    # https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html  XSS_PAYLOADS refference

#  --------------------------------------------------END----------------------------------------------------------------------
