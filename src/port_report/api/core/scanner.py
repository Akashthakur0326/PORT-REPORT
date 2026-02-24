import subprocess
import ipaddress
import socket # NEW: Required for DNS resolution
import xml.etree.ElementTree as ET

import subprocess
import xml.etree.ElementTree as ET
import re # NEW: We use regex for deterministic validation

def validate_target(target):
    """Deterministically validates if target is a clean IP or hostname."""
    # Only allow alphanumeric characters, dots, and hyphens. 
    # This inherently blocks command injection chars like ;, |, &, $, spaces
    if re.match(r"^[a-zA-Z0-9.-]+$", target):
        return True
    return False

# ... (Keep the rest of run_secure_scan and parse_nmap_xml exactly the same)

def run_secure_scan(ip):
    # Change default from the hardcoded IP to the service name!
    target = ip if ip else "victim" 

    if not validate_target(target):
        return {"error": f"Invalid or unresolvable target: {target}"}

    # Nmap handles hostnames perfectly, so we just pass it
    command = ["nmap", "-Pn", "-sT", "-sV", "-T4", "-oX", "-", target]
    
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=300) #more secure in case IP has more cmd attached using ; here we discard them 
        #With shell=True Python → Shell → Kernel → nmap || With shell=False Python → Kernel → nmap
        if result.returncode != 0:
            return {"error": "Nmap failed", "details": result.stderr}
        return parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out."}

def parse_nmap_xml(xml_data):    
    """Extracts data with defensive checks to prevent NoneType errors."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return {"error": "Failed to parse Nmap XML output"}

    results = []
    host_element = root.find('host')

    # IF NMAP FOUND NOTHING:
    if host_element is None:
        return {
            "target": "Unknown", 
            "open_ports": [], 
            "status": "No host found or host is down"
        }

    # Defensive check for address
    addr_element = host_element.find('address')
    target_addr = addr_element.get('addr') if addr_element is not None else "Unknown"

    ports_element = host_element.find('ports')
    if ports_element is not None:
        for port in ports_element.findall('port'):
            state = port.find('state').get('state')
            if state != 'open':#only care about open ports 
                continue 
            
            port_id = port.get('portid')
            service = port.find('service')
            
            if service is not None:
                cpe_element = service.find('cpe')# needed to find cve using NVD API
                cpe = cpe_element.text if cpe_element is not None else None
                
                results.append({
                    "port": int(port_id),
                    "protocol": port.get('protocol'),
                    "service_name": service.get('name', 'unknown'),
                    "product": service.get('product', 'unknown'),
                    "version": service.get('version', 'unknown'),
                    "cpe": cpe 
                })
                
    return {"target": target_addr, "open_ports": results}