import sys
import os
import json

# Ensure python can find the src directory when run from the scripts folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

# Import the compiled LangGraph workflow
from port_report.api.core.graph import app

def test_agent_workflow():
    # 'victim' is the internal Docker DNS name for Metasploitable
    target = "victim" 
    
    print(f"[*] Initializing Agent Graph for target: {target}")
    print("[*] Please wait. The agent is scanning, researching, attacking, and consulting the CISO...")
    
    # 1. Define the initial state
    initial_state = {
        "target_ip": target
    }
    
    try:
        # 2. Invoke the LangGraph workflow
        final_state = app.invoke(initial_state)
        
        print("\n" + "="*50)
        print("🚀 AGENT WORKFLOW COMPLETE 🚀")
        print("="*50 + "\n")
        
        # 3. Output the final synthesized JSON report
        if "final_json_report" in final_state:
            print("[+] Final CISO Report (JSON):")
            print(json.dumps(final_state["final_json_report"], indent=2))
        else:
            print("[-] No final report generated. Showing raw state:")
            # We truncate the output so it doesn't flood the terminal if something goes wrong
            print(str(final_state)[:1000])
            
        # 4. Error Checking
        if "errors" in final_state and final_state["errors"]:
            print("\n[!] Errors encountered during execution:")
            for err in final_state["errors"]:
                print(f"  - {err}")
                
    except Exception as e:
        print(f"\n[!] Fatal Error during graph execution: {e}")

if __name__ == "__main__":
    test_agent_workflow()