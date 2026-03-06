import chromadb

def test_query():
    # Connect to the running container
    client = chromadb.HttpClient(host='localhost', port=8001) # Use 8001 for Windows host access
    collection = client.get_collection(name="mitre_mitigations")

    # Test Case: We just hacked a database via default credentials
    query = "How to prevent unauthorized access to a database and default credentials"
    
    print(f"[*] Querying: {query}")
    results = collection.query(
        query_texts=[query],
        n_results=2
    )

    for i, doc in enumerate(results['documents'][0]):
        print(f"\n[+] Result {i+1}:")
        print(doc)

if __name__ == "__main__":
    test_query()