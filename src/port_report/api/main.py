from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

# We import the compiled LangGraph workflow from graph.py
from port_report.api.core.graph import app as agent_workflow

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Red Team Agent API", 
    description="Automated Pentest Agent"
)

# Define the expected JSON input payload
class AuditRequest(BaseModel):
    ip: str | None = "victim"  # Default to the lab container if none provided

@app.post("/api/v1/audit")
def perform_full_audit(req: AuditRequest):
    logger.info(f"[*] Received full audit request for target: {req.ip}")
    
    # 1. Initialize the LangGraph State
    # This must match the schema defined in your state.py AgentState
    initial_state = {
        "target_ip": req.ip
    }
    
    try:
        # 2. Invoke the Graph (This runs the entire automated sequence)
        logger.info("[*] Executing LangGraph state machine...")
        final_state = agent_workflow.invoke(initial_state)
        
        # 3. Check for explicit errors caught by our nodes
        if "errors" in final_state and final_state["errors"]:
            logger.warning(f"[!] Agent encountered errors during execution: {final_state['errors']}")
            # We don't fail completely here because the CISO node might have still generated a partial report
            
        # 4. Extract and validate the final CISO report
        if "final_json_report" in final_state:
            logger.info("[+] CISO report successfully generated.")
            return {
                "status": "success", 
                "target": req.ip,
                "report": final_state["final_json_report"]
            }
        else:
            logger.error("[-] Workflow completed but 'final_json_report' is missing from state.")
            raise HTTPException(status_code=500, detail="Agent failed to synthesize final report.")
            
    except Exception as e:
        logger.error(f"[!] FATAL GRAPH ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Agent Workflow Error: {str(e)}")

# Keep a simple ping endpoint for health checks
@app.get("/health")
def health_check():
    return {"status": "online", "agent": "ready"}