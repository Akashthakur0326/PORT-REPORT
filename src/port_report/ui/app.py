import streamlit as st
import requests

# Professional page config
st.set_page_config(page_title="Agentic Pentester", page_icon="🛡️", layout="wide")
st.title("🛡️ Autonomous Red Team Agent & CISO Dashboard")
st.markdown("Automated Reconnaissance, Exploitation, and Mitigation Synthesis via LangGraph.")

st.divider()

# Input field
target_ip = st.text_input("Enter Target IP (Leave blank for 'victim' sandbox):", value="")

if st.button("Initiate Agentic Audit", type="primary"):
    target = target_ip if target_ip else "victim"
    
    # We use st.status to show the pipeline steps to the user while the blocking request runs
    with st.status(f"Executing LangGraph Pipeline on {target}...", expanded=True) as status:
        st.markdown("⏳ **Node 1 (Scanner):** Running secure Nmap reconnaissance...")
        st.markdown("⏳ **Node 2 (Researcher):** Querying Vulners API for Threat Intel...")
        st.markdown("⏳ **Node 3 (Attacker):** Executing deterministic exploits & querying ChromaDB...")
        st.markdown("⏳ **Node 4 (CISO):** Llama-3.3-70B synthesizing final report...")
        
        try:
            # ADDED TIMEOUT: Crucial for long-running agent workflows
            response = requests.post(
                "http://backend:8000/api/v1/audit", 
                json={"ip": target},
                timeout=120 # Give the agent 2 minutes to finish the whole graph
            )
            
            if response.status_code == 200:
                status.update(label="Audit Complete!", state="complete", expanded=False)
                data = response.json()
                report = data.get("report", {})
                
                st.divider()
                st.subheader(f"📊 Final CISO Report for `{target}`")
                
                # Parse and render the structured JSON from the LLM
                # We requested 'Critical', 'High', 'Medium' in the CISO prompt
                for severity, color in [("Critical", "🔴"), ("High", "🟠"), ("Medium", "🟡")]:
                    if severity in report and isinstance(report[severity], list):
                        st.markdown(f"### {color} {severity} Findings")
                        for finding in report[severity]:
                            with st.expander(f"{finding.get('vulnerability', 'Unknown Vulnerability')}"):
                                st.markdown("**Evidence Found:**")
                                st.code(finding.get('evidence_found', 'No evidence provided.'))
                                st.markdown("**Mitigation Steps:**")
                                st.info(finding.get('mitigation_steps', 'No mitigation provided.'))
                
                # Fallback: Just in case the LLM hallucinates a slightly different JSON structure
                with st.expander("⚙️ View Raw CISO JSON (Debug)"):
                    st.json(report)
                    
            else:
                status.update(label="Audit Failed", state="error", expanded=True)
                st.error(f"Backend Error: {response.text}")
                
        except requests.exceptions.ReadTimeout:
            status.update(label="Timeout Execution", state="error")
            st.error("[!] The agent took longer than 120 seconds. The LLM rate limits or Nmap scan might be hanging.")
        except requests.exceptions.ConnectionError:
            status.update(label="Connection Error", state="error")
            st.error("[!] Failed to connect to the FastAPI backend. Is the 'agent_backend' container healthy?")