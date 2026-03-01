import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API")
SHODAN_API_KEY = os.getenv("SHODAN_API")

class VulnerabilityResearcher:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.shodan_url = "https://cvedb.shodan.io/cves"

    def fetch_cves(self, cpe):
        """Dual-source lookup for target CPE."""
        print(f"[*] Analyzing vulnerabilities for {cpe}...")
        
        # 1. Shodan for fast ID list
        try:
            res = requests.get(f"{self.shodan_url}?cpe23={cpe}")
            cve_ids = [item['cve_id'] for item in res.json().get('cves', [])]
        except Exception as e:
            print(f"[!] Shodan Error: {e}")
            return []

        # 2. NVD for deep descriptions (NVD is slow, so we pick the top 3 highest impact)
        findings = []
        for cve_id in cve_ids[:3]: # Limit for performance/rate-limits
            details = self._get_nvd_details(cve_id)
            if details:
                findings.append(details)
            time.sleep(6) # Strict NVD rate limit compliance
            
        return findings

    def _get_nvd_details(self, cve_id):
        headers = {"apiKey": NVD_API_KEY}
        try:
            res = requests.get(f"{self.nvd_url}?cveId={cve_id}", headers=headers)
            if res.status_code == 200:
                vuln = res.json().get('vulnerabilities', [{}])[0].get('cve', {})
                desc = vuln.get('descriptions', [{}])[0].get('value', "")
                return {"id": cve_id, "description": desc}
        except Exception:
            return None
        return None