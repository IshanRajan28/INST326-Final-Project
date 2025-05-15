import pytest
from API import fetch_live_malicious_ips, get_malicious_ips, HISTORICAL_IPS

# Replace with your actual API key
TEST_API_KEY = ""  

def test_fetch_live_malicious_ips():
    """Test the live API fetcher with valid API key"""
    result = fetch_live_malicious_ips(TEST_API_KEY)
    assert isinstance(result, list)
    if result:  # Only check contents if API returned data
        assert all(isinstance(ip, str) for ip in result)
        assert len(result) <= 5  # Default limit

def test_fetch_live_malicious_ips_invalid_key():
    """Test with invalid API key"""
    result = fetch_live_malicious_ips("invalid_key")
    assert result == []  # Should return empty list on failure

def test_get_malicious_ips_live():
    """Test getter with live API (success case)"""
    result = get_malicious_ips(TEST_API_KEY)
    assert isinstance(result, list)
    # Either live or historical
    assert len(result) > 0 

def test_get_malicious_ips_fallback():
    """Test getter falls back to historical data"""
    # Mock failed API call by passing None
    result = get_malicious_ips(None)
    assert result == HISTORICAL_IPS
    assert len(result) == 4

def test_historical_ips_unchanged():
    """Ensure historical IPs maintain their integrity"""
    assert len(HISTORICAL_IPS) == 4
    # Basic IP format check
    assert all('.' in ip for ip in HISTORICAL_IPS)