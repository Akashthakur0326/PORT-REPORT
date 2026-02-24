import streamlit as st
import requests

st.set_page_config(page_title="Agentic Pentester", layout="wide")
st.title("Red Team Autonomous Agent")

# Input field
target_ip = st.text_input("Enter Target IP (Leave blank for default sandbox):", value="")

if st.button("Initiate Reconnaissance"):
    with st.spinner(f"Scanning {target_ip if target_ip else 'default sandbox'}... This takes ~1 minute."):
        try:
            # Send the IP to the FastAPI container
            response = requests.post(
                "http://backend:8000/api/v1/scan", 
                json={"ip": target_ip}
            )
            
            if response.status_code == 200:
                st.success("Reconnaissance Complete!")
                st.json(response.json()) # Beautifully renders the Nmap JSON
            else:
                st.error(f"Error: {response.json().get('detail')}")
                
        except requests.exceptions.ConnectionError:
            st.error("Failed to connect to the Scanner Backend. Is the Docker container running?")