import os
import pytest
from report_generator import generate_summary_report, format_threat_details, save_report

@pytest.fixture
def sample_threats():
    return {
        "failed_logins": [
            {"ip": "192.168.1.1", "username": "root", "timestamp": "2025-05-07 09:00"}
        ],
        "suspicious_ips": [
            {"ip": "10.0.0.1", "timestamp": "2025-05-07 03:21"}
        ]
    }

def test_generate_summary_report_multiple_types(sample_threats):
    report = generate_summary_report(sample_threats)
    assert "Failed_Logins: 1 found" in report
    assert "Suspicious_Ips: 1 found" in report

def test_generate_summary_report_empty():
    report = generate_summary_report({})
    assert report.strip() == "No threats found."

def test_format_threat_details_full_fields():
    threats = [{"ip": "1.2.3.4", "username": "user1", "timestamp": "2025-05-07"}]
    result = format_threat_details("failed_logins", threats)
    assert "IP: 1.2.3.4" in result
    assert "User: user1" in result
    assert "Time: 2025-05-07" in result

def test_format_threat_details_missing_fields():
    threats = [{"ip": "1.2.3.4"}]
    result = format_threat_details("suspicious_ips", threats)
    assert "IP: 1.2.3.4" in result
    assert "User:" not in result
    assert "Time:" not in result

def test_format_threat_details_empty_list():
    result = format_threat_details("privilege_escalation", [])
    assert "No details available for privilege_escalation threats." in result

def test_save_report_success(tmp_path):
    test_file = tmp_path / "report.txt"
    content = "Sample Report"
    result = save_report(content, str(test_file))
    assert result is True
    assert test_file.read_text() == content

def test_save_report_failure(monkeypatch):
    def bad_open(*args, **kwargs):
        raise IOError("Simulated failure")
    monkeypatch.setattr("builtins.open", bad_open)
    assert save_report("data", "fake_path.txt") is False
