import sys
import os

# Set up paths so we can import from src/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from port_report.api.core.researcher import VulnerabilityResearcher

def test_research_node():
    print("🔬 Testing Research Node (Shodan + NVD)...")
    researcher = VulnerabilityResearcher()
    
    # Using a known vulnerable CPE (vsftpd 2.3.4) in 2.3 format
    test_cpe = "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"
    
    findings = researcher.fetch_cves(test_cpe)
    
    if findings:
        print(f"\n✅ SUCCESS: Found {len(findings)} CVEs")
        for f in findings:
            print(f"  - [{f['id']}]: {f['description'][:100]}...")
    else:
        print("\n❌ FAILURE: No CVEs returned. Check Shodan API key or CPE format.")

if __name__ == "__main__":
    test_research_node()