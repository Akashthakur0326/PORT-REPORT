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
        st.markdown("⏳ **Node 2 (Researcher):** Querying NVD API for Threat Intel...")
        st.markdown("⏳ **Node 3 (Attacker):** Executing deterministic exploits & querying ChromaDB...")
        st.markdown("⏳ **Node 4 (CISO):** Llama-3.3-70B synthesizing final report...")
        
        try:
            # INCREASED TIMEOUT: The agent does a lot of work and sleeps to avoid rate limits.
            # We give it 300 seconds (5 minutes) to finish.
            response = requests.post(
                "http://backend:8000/api/v1/audit", 
                json={"ip": target},
                timeout=400 
            )
            
            if response.status_code == 200:
                status.update(label="Audit Complete!", state="complete", expanded=False)
                data = response.json()
                report = data.get("report", {})
                
                st.divider()
                st.subheader(f"📊 Final CISO Report for `{target}`")
                
                # Parse and render the structured JSON from the LLM
                for severity, color in [("Critical", "🔴"), ("High", "🟠"), ("Medium", "🟡")]:
                    if severity in report.get("findings", {}) and isinstance(report["findings"][severity], list):
                        findings_list = report["findings"][severity]
                        if findings_list: # Only show if there are actual findings
                            st.markdown(f"### {color} {severity} Findings")
                            for finding in findings_list:
                                with st.expander(f"{finding.get('vulnerability', 'Unknown Vulnerability')}"):
                                    st.markdown("**Evidence Found:**")
                                    st.code(finding.get('evidence_found', 'No evidence provided.'))
                                    st.markdown("**Mitigation Steps:**")
                                    
                                    # Handle both list and string formats for mitigations
                                    mitigation_data = finding.get('mitigation_steps', [])
                                    if isinstance(mitigation_data, list):
                                        for step in mitigation_data:
                                            st.info(step)
                                    else:
                                        st.info(mitigation_data)
                
                # Render General Recommendations
                if "recommendations" in report:
                    st.divider()
                    st.subheader("🛡️ General Hardening Recommendations")
                    
                    if "general_hardening" in report["recommendations"]:
                        st.markdown("#### Strategic Actions")
                        for rec in report["recommendations"]["general_hardening"]:
                            st.markdown(f"- {rec}")
                            
                    if "open_ports" in report["recommendations"]:
                        with st.expander("View Unexploited Open Ports"):
                            st.table(report["recommendations"]["open_ports"])
                
                # Fallback Debug View
                with st.expander("⚙️ View Raw CISO JSON (Debug)"):
                    st.json(report)
                    
            else:
                status.update(label="Audit Failed", state="error", expanded=True)
                st.error(f"Backend Error: {response.text}")
                
        except requests.exceptions.ReadTimeout:
            status.update(label="Timeout Execution", state="error")
            st.error("[!] The agent took longer than 300 seconds to complete the audit. Check backend logs for progress.")
        except requests.exceptions.ConnectionError:
            status.update(label="Connection Error", state="error")
            st.error("[!] Failed to connect to the FastAPI backend. Is the 'agent_backend' container healthy?")