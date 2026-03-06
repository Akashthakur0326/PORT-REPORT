import json
import re
import os
from langgraph.graph import StateGraph, END
from .state import AgentState
from .scanner import run_secure_scan
from .researcher import VulnerabilityResearcher
from .attack import execute_attack_flow
from .remedy_context import RemedyContextBuilder
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

# --- INITIALIZATION ---
# Note: Ensure VULNERS_API and GROQ_API_KEY are in your .env
researcher = VulnerabilityResearcher()
remedy_tool = RemedyContextBuilder(use_docker_network=True)
llm = ChatGroq(
    model="llama-3.3-70b-versatile", 
    temperature=0, 
    groq_api_key=os.getenv("GROQ_API_KEY")
)

CISO_PROMPT = """
You are a Senior Cyber Security Auditor (CISO). 
Your task is to review raw technical logs and generate a professional, high-level JSON report.

INPUT DATA:
- Target IP: {target_ip}
- Scan Info: {scan_results}
- Attack/Remedy Data: {attack_reports}

STRICT REQUIREMENTS:
1. You must output VALID JSON only.
2. Group findings by 'Critical', 'High', 'Medium'.
3. For each finding, provide: 'vulnerability', 'evidence_found', 'mitigation_steps'.
4. If no successful attacks occurred, summarize the open ports and recommend general hardening.
5. Do not include conversational filler or markdown headers outside the JSON.
"""

def sanitize_json_response(content: str) -> str:
    """Strips Markdown code blocks to ensure json.loads() works."""
    clean_content = re.sub(r'```json\s*|```', '', content).strip()
    return clean_content

# --- NODES ---

def scan_node(state: AgentState):
    """Deterministic Nmap Scan"""
    print(f"[*] Starting scan on {state['target_ip']}")
    results = run_secure_scan(state['target_ip'])
    return {"scan_results": results}

def research_and_attack_node(state: AgentState):
    """Accumulator Pattern: Process all CPEs in one node"""
    all_vulns = []
    all_reports = []
    
    ports = state['scan_results'].get('open_ports', [])
    if not ports:
        return {"vulnerabilities": [], "attack_reports": []}

    for port_info in ports:
        cpe = port_info.get('cpe')
        if not cpe: continue
        
        # 1. Research CVEs
        found_cves = researcher.fetch_cves(cpe)
        all_vulns.extend(found_cves)
        
        # 2. Attempt Attacks & Build Remedy Context for each CVE
        for cve in found_cves:
            attack_res = execute_attack_flow(cve['id'], state['target_ip'])
            context = remedy_tool.build_llm_context(attack_res, raw_cpe=cpe)
            all_reports.append(context)
            
    return {"vulnerabilities": all_vulns, "attack_reports": all_reports}

def route_after_research(state: AgentState):
    """Router: deciding to synthesize or end."""
    if not state.get("attack_reports") or len(state["attack_reports"]) == 0:
        print("[*] No vulnerabilities found to analyze.")
        return "skip_to_end"
    return "proceed_to_ciso"

def ciso_synthesis_node(state: AgentState):
    """The Cognition Node"""
    condensed_reports = []
    for report in state['attack_reports']:
        condensed_reports.append({
            "cve": report['target_data']['cve_id'],
            "success": report['target_data']['attack_successful'],
            "mitigations": report['recommended_mitigations'][:1]
        })

    prompt = CISO_PROMPT.format(
        target_ip=state['target_ip'],
        scan_results=state['scan_results'],
        attack_reports=condensed_reports
    )
    
    response = llm.invoke(prompt)
    clean_json_str = sanitize_json_response(response.content)
    
    try:
        report_json = json.loads(clean_json_str)
        return {"final_json_report": report_json}
    except Exception as e:
        return {
            "errors": [f"JSON Parsing Error: {str(e)}"], 
            "final_json_report": {"raw_summary": clean_json_str[:500]}
        }

# --- GRAPH CONSTRUCTION ---

workflow = StateGraph(AgentState)

workflow.add_node("scanner", scan_node)
workflow.add_node("researcher_attacker", research_and_attack_node)
workflow.add_node("ciso", ciso_synthesis_node)

workflow.set_entry_point("scanner")
workflow.add_edge("scanner", "researcher_attacker")

# FIX: Added the missing route_after_research function reference
workflow.add_conditional_edges(
    "researcher_attacker",
    route_after_research,
    {
        "proceed_to_ciso": "ciso",
        "skip_to_end": END
    }
)

workflow.add_edge("ciso", END)

app = workflow.compile()
