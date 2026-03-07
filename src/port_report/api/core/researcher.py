import os
import requests
import time
from dotenv import load_dotenv

# THE FIX: Import our known attack templates to guide the research
from .templates import MASTER_TEMPLATES

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API")

"""
CPE → Extract Keywords → Query NVD Database → Prioritize Known Exploits → Retrieve details
"""
class VulnerabilityResearcher:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_cves(self, cpe):
        parts = str(cpe).split(':')
        if len(parts) >= 6:
            keyword_query = f"{parts[3]} {parts[4]} {parts[5]}".replace('_', ' ')
        else:
            keyword_query = str(cpe).replace('cpe:/a:', '').replace(':', ' ')

        print(f"[*] Querying NVD for Keywords: '{keyword_query}'")
        
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        url = f"{self.nvd_url}?keywordSearch={keyword_query}"
        
        try:
            res = requests.get(url, headers=headers, timeout=15)
            
            if res.status_code == 200:
                data = res.json()
                vulns = data.get('vulnerabilities', [])
                
                # 1. Extract ALL CVEs returned by NVD
                extracted_cves = []
                for v in vulns: 
                    cve_data = v.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    descriptions = cve_data.get('descriptions', [])
                    desc_text = "No description available."
                    for d in descriptions:
                        if d.get('lang') == 'en':
                            desc_text = d.get('value')
                            break
                            
                    if cve_id:
                        extracted_cves.append({"id": cve_id, "description": desc_text})
                
                # 2. THE PREDATOR LOGIC: Sort the list. 
                # If the CVE ID is a key in MASTER_TEMPLATES, it gets pushed to the front (True > False).
                extracted_cves.sort(key=lambda x: x['id'] in MASTER_TEMPLATES, reverse=True)
                
                # 3. Take only the top 3 after sorting
                findings = extracted_cves[:3]
                
                # Loud Logging to prove it worked
                for f in findings:
                    if f['id'] in MASTER_TEMPLATES:
                        print(f"    [★] Weaponized Template Found for: {f['id']} - Prioritizing!")

                time.sleep(6) # Strict NVD rate limit compliance
                return findings
            
            elif res.status_code == 403:
                print("[!] NVD API Error 403: Rate Limited. Check your API key.")
            elif res.status_code == 503:
                print("[!] NVD API Error 503: Service Unavailable.")
            else:
                print(f"[!] NVD HTTP Error: {res.status_code}")
                
        except Exception as e:
            print(f"[!] NVD Connection Error: {e}")

        time.sleep(6) 
        return []