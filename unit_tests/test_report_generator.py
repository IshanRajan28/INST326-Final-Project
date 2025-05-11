"""
Report Generator Unit Tests

Validates core reporting functionality including:
- Threat summary generation
- Detailed threat formatting
- Report file operations
- Error handling scenarios
"""

import os
import pytest
from report_generator import generate_summary_report, format_threat_details, save_report

@pytest.fixture
def sample_threats():
    """Provides standard threat data for testing
    Contains:
    - failed_logins: One failed login attempt
    - suspicious_ips: One suspicious IP
    """
    return {
        "failed_logins": [
            {"ip": "192.168.1.1", "username": "root", "timestamp": "2025-05-07 09:00"}
        ],
        "suspicious_ips": [
            {"ip": "10.0.0.1", "timestamp": "2025-05-07 03:21"}
        ]
    }

def test_generate_summary_report_multiple_types(sample_threats):
    """Test report generation with multiple threat types
    - Verifies all threat categories appear in output
    - Checks correct count formatting
    """
    report = generate_summary_report(sample_threats)
    assert "Failed_Logins: 1 found" in report
    assert "Suspicious_Ips: 1 found" in report

def test_generate_summary_report_empty():
    """Test empty threat dictionary handling
    - Ensures proper message when no threats exist
    - Verifies whitespace formatting
    """
    report = generate_summary_report({})
    assert report.strip() == "No threats found."

def test_format_threat_details_full_fields():
    """Test threat formatting with complete data
    - Verifies all fields (IP, user, timestamp) display
    - Checks proper field ordering
    """
    threats = [{"ip": "1.2.3.4", "username": "user1", "timestamp": "2025-05-07"}]
    result = format_threat_details("failed_logins", threats)
    assert "IP: 1.2.3.4" in result
    assert "User: user1" in result
    assert "Time: 2025-05-07" in result

def test_format_threat_details_missing_fields():
    """Test formatting with partial threat data
    - Validates graceful handling of missing fields
    - Ensures only available fields display
    """
    threats = [{"ip": "1.2.3.4"}]
    result = format_threat_details("suspicious_ips", threats)
    assert "IP: 1.2.3.4" in result
    assert "User:" not in result
    assert "Time:" not in result

def test_format_threat_details_empty_list():
    """Test empty threat list handling
    - Verifies recommendation still appears
    - Checks minimal output formatting
    """
    result = format_threat_details("privilege_escalation", [])
    assert "Recommendation: Monitor privilege escalation" in result
    assert result.count('\n') == 1

def test_save_report_success(tmp_path):
    """Test successful report file creation
    - Verifies file is created with correct content
    - Checks return status is True
    """
    test_file = tmp_path / "report.txt"
    content = "Sample Report"
    result = save_report(content, str(test_file))
    assert result is True
    assert test_file.read_text() == content

def test_save_report_failure(monkeypatch):
    """Test filesystem error handling
    - Simulates IOError during save
    - Verifies False return value
    """
    def bad_open(*args, **kwargs):
        raise IOError("Simulated failure")
    monkeypatch.setattr("builtins.open", bad_open)
    assert save_report("data", "fake_path.txt") is False