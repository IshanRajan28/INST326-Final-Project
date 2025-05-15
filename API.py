import requests
from typing import List, Optional

# The following IPs were identified from public threat intelligence sources:
# AbuseIPDB, AlienVault OTX, and Spamhaus. Labels reflect known activity
# reported on those platforms as of 2024
# Note: These IPs were flagged as malicious in the past (e.g., via AbuseIPDB, 
# AlienVault OTX), but may not be currently active threats.
# Historical malicious IPs (fallback)
HISTORICAL_IPS = [
    '45.227.225.6',   # SSH brute-force (AbuseIPDB)
    '185.232.67.3',   # Phishing (Spamhaus)
    '185.6.233.3',    # Botnet C2 (AlienVault)
    '198.144.121.93'  # Malware (AbuseIPDB)
]

def fetch_live_malicious_ips(api_key: str, limit: int = 5) -> List[str]:
    """
    Fetches current malicious IPs from AbuseIPDB API
    
    Args:
        api_key (str): Valid AbuseIPDB API key.
        limit (int): Maximum IPs to return.
        
    Returns:
        List of IP addresses or empty list on failure
    """
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": api_key.strip(), "Accept": "application/json"},
            params={"limit": limit},
            timeout=5
        )
        response.raise_for_status()
        return [entry['ipAddress'] for entry in response.json().get('data', [])]
    except (requests.RequestException, ValueError, KeyError):
        return []


def get_malicious_ips(api_key: Optional[str] = None) -> List[str]:
    """
    Gets malicious IPs, trying live API first with fallback to historical data
    
    Args:
        api_key: Optional AbuseIPDB API key
        
    Returns:
        List of malicious IP addresses (live or historical)
    """
    if api_key:
        live_ips = fetch_live_malicious_ips(api_key)
        if live_ips:
            return live_ips
    return HISTORICAL_IPS

