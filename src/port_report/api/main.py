from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from port_report.api.core.scanner import run_secure_scan

app = FastAPI(title="Red Team Agent API")

# Define the expected JSON input payload
class ScanRequest(BaseModel):
    ip: str | None = None

@app.post("/api/v1/scan")
def perform_scan(req: ScanRequest):
    print(f"Received scan request for: {req.ip}")
    result = run_secure_scan(req.ip)
    
    if "error" in result:
        # THIS WILL TELL YOU EXACTLY WHAT WENT WRONG IN THE LOGS
        print(f"[!] SCAN FAILED: {result['error']}") 
        raise HTTPException(status_code=400, detail=result["error"])
    
    return result