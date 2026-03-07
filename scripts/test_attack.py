import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from port_report.api.core.attack import execute_attack_flow

def test_attack_node():
    print("⚔️ Testing Attack Node (Postgres + Exploit Execution)...")
    
    # We use the known vsftpd backdoor CVE
    target_cve = "CVE-2011-2523"
    target_ip = "172.18.0.2" # The standard internal IP for 'victim'
    
    try:
        result = execute_attack_flow(target_cve, target_ip)
        
        print("\n" + "="*30)
        print(f"CVE: {result.get('cve')}")
        print(f"VULNERABLE: {result.get('is_vulnerable')}")
        print(f"EVIDENCE: {result.get('evidence')}")
        print("="*30)
        
        if result.get('is_vulnerable'):
            print("🔥 SUCCESS: Exploit triggered and validated!")
        else:
            print("🛡️ FAIL: Exploit ran but validation failed (Safe/Patched).")
            
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")

if __name__ == "__main__":
    test_attack_node()