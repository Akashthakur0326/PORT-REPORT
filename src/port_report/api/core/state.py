from typing import TypedDict, List, Dict, Any

class AgentState(TypedDict):
    target_ip: str
    scan_results: Dict[str, Any]       # Output from scanner.py
    vulnerabilities: List[Dict]        # Aggregated CVEs from researcher.py
    attack_reports: List[Dict]         # Results from attack.py + remedy_context.py
    final_json_report: Dict[str, Any]  # The final synthesis from Groq
    errors: List[str]                  # Traceability for when things break