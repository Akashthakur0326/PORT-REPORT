"""
ChromaDB Seed Script: MITRE ATT&CK Mitigations
Fetches the official STIX 2.0 JSON from MITRE and embeds it into ChromaDB for RAG.
"""

import requests
import chromadb
import time

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CHROMA_HOST = "chroma" # Docker service name
CHROMA_PORT = 8000

def fetch_mitre_data():
    print("[*] Fetching official MITRE ATT&CK dataset...")
    response = requests.get(MITRE_URL)
    response.raise_for_status()
    return response.json()

def seed_database():
    print(f"[*] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}...")
    
    # Retry logic because Chroma takes a few seconds to start up in Docker
    client = None
    for _ in range(5):
        try:
            client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            client.heartbeat()
            break
        except Exception:
            print("[!] Chroma not ready yet, retrying in 2 seconds...")
            time.sleep(2)
            
    if not client:
        print("[-] FATAL: Could not connect to ChromaDB.")
        return

    # Create or get the collection (table)
    collection = client.get_or_create_collection(name="mitre_mitigations")
    
    # Check if we already seeded to avoid duplicates
    if collection.count() > 0:
        print(f"[+] Collection 'mitre_mitigations' already exists with {collection.count()} records. Skipping seed.")
        return

    data = fetch_mitre_data()
    
    # In STIX terminology, a mitigation is a 'course-of-action'
    mitigations = [obj for obj in data.get('objects', []) if obj.get('type') == 'course-of-action']
    
    print(f"[*] Found {len(mitigations)} mitigations. Generating embeddings (this may take a minute)...")
    
    ids = []
    documents = []
    metadatas = []
    
    for m in mitigations:
        # Get the MITRE ID (e.g., M1036) or fallback to internal ID
        ext_refs = m.get('external_references', [])
        m_id = ext_refs[0].get('external_id') if ext_refs else m.get('id')
        
        name = m.get('name', 'Unknown Mitigation')
        desc = m.get('description', 'No description provided.')
        
        ids.append(m_id)
        # We embed the name and description so semantic search finds it easily
        documents.append(f"Mitigation Name: {name}\nDescription: {desc}")
        metadatas.append({"name": name, "source": "mitre-attack"})

    # Batch insert into ChromaDB
    # Chroma will automatically download a lightweight embedding model the first time this runs
    batch_size = 100
    for i in range(0, len(ids), batch_size):
        collection.add(
            ids=ids[i:i+batch_size],
            documents=documents[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size]
        )
        print(f"    -> Inserted batch {i} to {i+batch_size}")

    print(f"✅ SUCCESS: Seeded {collection.count()} mitigations into ChromaDB.")

if __name__ == "__main__":
    seed_database()