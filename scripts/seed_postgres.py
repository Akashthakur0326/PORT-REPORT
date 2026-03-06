"""
PostgreSQL Seed Script: Attack Templates
Parses templates.py and pushes the execution blueprints to the agent_brain DB.
"""

import psycopg2
import json
import time
import sys
import os

# Add the src directory to the path so we can import the templates
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from port_report.api.core.templates import MASTER_TEMPLATES

DB_CONFIG = {
    "dbname": "agent_brain",
    "user": "agent",
    "password": "agentpassword",
    "host": "db", 
    "port": 5432
}

def seed_postgres():
    print("[*] Connecting to PostgreSQL (agent_brain)...")
    
    conn = None
    for _ in range(5):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            break
        except Exception:
            print("[!] Database not ready, retrying in 2 seconds...")
            time.sleep(2)

    if not conn:
        print("[-] FATAL: Could not connect to Postgres.")
        return

    cur = conn.cursor()

    # 1. Create the table using JSONB for performance and native dictionary casting
    print("[*] Ensuring 'validation_templates' table exists...")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS validation_templates (
            cve_id VARCHAR(100) PRIMARY KEY,
            template_type VARCHAR(50) NOT NULL,
            params JSONB NOT NULL,
            validation_rule JSONB NOT NULL
        );
    """)
    conn.commit()

    # 2. Iterate and UPSERT (Insert, or Update if it already exists)
    print(f"[*] Found {len(MASTER_TEMPLATES)} templates. Syncing to database...")
    
    upsert_query = """
        INSERT INTO validation_templates (cve_id, template_type, params, validation_rule)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            template_type = EXCLUDED.template_type,
            params = EXCLUDED.params,
            validation_rule = EXCLUDED.validation_rule;
    """

    for cve_id, data in MASTER_TEMPLATES.items():
        try:
            # We must use json.dumps() to format the dicts for the JSONB columns
            cur.execute(upsert_query, (
                cve_id,
                data["executor"],
                json.dumps(data["params"]),
                json.dumps(data["validation"])
            ))
            print(f"    -> Synced: {cve_id} ({data['executor']})")
        except Exception as e:
            print(f"    [!] Failed to sync {cve_id}: {e}")
            conn.rollback()

    conn.commit()
    cur.close()
    conn.close()
    print("✅ SUCCESS: Postgres database is seeded and ready for attacks.")

if __name__ == "__main__":
    seed_postgres()