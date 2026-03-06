import os
import json
import chromadb
import vulners
from dotenv import load_dotenv

load_dotenv()

class RemedyContextBuilder:
    def __init__(self, use_docker_network=True):
        """
        Initializes connections to external APIs and internal Vector DB.
        """
        # 1. Initialize Vulners
        api_key = os.getenv("VULNERS_API") 
        if not api_key:
            print("[!] Warning: VULNERS_API not found in .env.")
            self.vulners_client = None
        else:
            self.vulners_client = vulners.VulnersApi(api_key=api_key)

        # 2. Initialize ChromaDB
        chroma_host = 'chroma' if use_docker_network else '127.0.0.1'
        chroma_port = 8000 if use_docker_network else 8001
        
        try:
            self.chroma_client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
            self.chroma_client.heartbeat()
            self.collection = self.chroma_client.get_collection(name="mitre_mitigations")
            print(f"[+] Connected to ChromaDB at {chroma_host}:{chroma_port}")
        except Exception as e:
            print(f"[!] Critical: ChromaDB connection failed: {e}")
            self.collection = None

    def _convert_cpe_2_2_to_2_3(self, nmap_cpe: str) -> str:
        if not nmap_cpe or not str(nmap_cpe).startswith("cpe:/"):
            return nmap_cpe
        core = nmap_cpe.replace("cpe:/", "")
        parts = core.split(":")
        while len(parts) < 11:
            parts.append("*")
        return f"cpe:2.3:{':'.join(parts)}"

    def _get_vulners_intelligence(self, cve_id: str) -> dict:
        """
        Hits Vulners API using the specific search method for bulletins.
        """
        if not self.vulners_client:
            return {"error": "Vulners API client not initialized."}

        try:
            results = self.vulners_client.search.search_bulletins_all(cve_id, limit=1)
            
            if not results:
                return {"description": "No data found on Vulners.", "cvss": "Unknown"}

            doc = results[0]
            return {
                "title": doc.get("title", cve_id),
                "description": doc.get("description", "No description available."),
                "cvss_score": doc.get("cvss", {}).get("score", "N/A"),
                "exploit_available": doc.get("exploitsCount", 0) > 0,
                "reference_link": doc.get("href", "")
            }
        except Exception as e:
            try:
                results = self.vulners_client.search(cve_id, limit=1)
                doc = results[0]
                return {"title": doc.get("title"), "description": doc.get("description")}
            except:
                return {"error": f"API request failed: {str(e)}"}

    def _get_mitre_mitigations(self, search_query: str, n_results=2) -> list:
        """
        Queries ChromaDB and TRUNCATES output to prevent token overflow.
        """
        if not self.collection:
            return ["ChromaDB offline."]

        try:
            results = self.collection.query(query_texts=[search_query], n_results=n_results)
            
            if results and 'documents' in results and len(results['documents']) > 0:
                # TRUNCATE to 750 characters so the LLM doesn't get a wall of text
                return [doc[:750] + "..." for doc in results['documents'][0]]
            return ["No relevant MITRE mitigations found."]
        except Exception as e:
            return [f"Vector DB Error: {str(e)}"]
        

    def build_llm_context(self, attack_result: dict, raw_cpe: str = None) -> dict:
        """
        Takes the output of attack.py directly.
        """
        cve_id = attack_result.get("cve", "UNKNOWN")
        is_vuln = attack_result.get("is_vulnerable", False)
        
        print(f"[*] Fetching Intel for {cve_id}...")

        modern_cpe = self._convert_cpe_2_2_to_2_3(raw_cpe) if raw_cpe else "Unknown"
        threat_intel = self._get_vulners_intelligence(cve_id)
        
        # Use description for vector search, fallback to title/CVE
        search_query = threat_intel.get("description", threat_intel.get("title", cve_id))
        mitigations = self._get_mitre_mitigations(search_query)

        return {
            "target_data": {
                "cve_id": cve_id,
                "cpe_2_3": modern_cpe,
                "attack_successful": is_vuln,
                "attack_evidence": attack_result.get("evidence", "No evidence.")
            },
            "threat_intelligence": threat_intel,
            "recommended_mitigations": mitigations
        }