import pytest
import tempfile
import os
import argparse
import sys
from io import StringIO

from main import parse_arguments  # Moved to the top
from log_parser import extract_log_entries
from log_analyzer import LogAnalyzer
from report_generator import (
    generate_summary_report,
    format_threat_details,
    save_report,
    display_report
)

# ----------------------------
# Tests for log_parser.py
# ----------------------------

def test_extract_log_entries_valid_lines():
    log_data = """
Jan  1 00:00:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 22 ssh2
Jan  1 00:01:01 server sshd[12346]: Accepted password for user bob from 192.168.1.2 port 22 ssh2
"""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp:
        temp.write(log_data)
        temp_path = temp.name

    result = extract_log_entries(temp_path)
    assert isinstance(result, list)
    assert len(result) == 2
    assert "Failed password" in result[0]
    assert "Accepted password" in result[1]

    os.remove(temp_path)

def test_extract_log_entries_file_not_found():
    with pytest.raises(FileNotFoundError):
        extract_log_entries("nonexistent_file.log")

# ----------------------------
# Tests for log_analyzer.py
# ----------------------------

@pytest.fixture
def sample_log_file():
    data = """
Jan  1 23:00:01 server sshd[12345]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
Jan  1 23:00:05 server sshd[12346]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
Jan  1 23:00:10 server sshd[12347]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
Jan  1 01:00:00 server sshd[12348]: Accepted password for user root from 192.168.1.2 port 22 ssh2
"""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp:
        temp.write(data)
        temp_path = temp.name
    yield temp_path
    os.remove(temp_path)

def test_failed_login_detection(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file, threshold=3)
    analyzer.parse_log_file()
    summary = analyzer.detect_threats()
    assert "failed_logins" in summary
    assert len(summary["failed_logins"]) == 1
    assert summary["failed_logins"][0]["ip"] == "10.0.0.1"

def test_suspicious_ip_detection(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file, suspicious_ip_list=["192.168.1.2"])
    analyzer.parse_log_file()
    summary = analyzer.detect_threats()
    assert "suspicious_ips" in summary
    assert "192.168.1.2" in summary["suspicious_ips"]

def test_unusual_access_time_detection(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file, start_time=22, end_time=6)
    analyzer.parse_log_file()
    summary = analyzer.detect_threats()
    assert "unusual_access_times" in summary
    assert any("10.0.0.1" in str(t) or "192.168.1.2" in str(t) for t in summary["unusual_access_times"])

def test_privilege_escalation_detection(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    summary = analyzer.detect_threats()
    assert "privilege_escalations" in summary
    assert any("root" in str(t) for t in summary["privilege_escalations"])

# ----------------------------
# Tests for report_generator.py
# ----------------------------

def test_generate_summary_report_multiple_threats():
    threats = {
        "failed_logins": [{"ip": "1.1.1.1", "username": "admin", "timestamp": "01:00"}],
        "suspicious_ips": ["5.5.5.5"],
    }
    report = generate_summary_report(threats)
    assert "Failed_Logins: 1 found" in report
    assert "Suspicious_Ips: 1 found" in report
    assert "IP: 1.1.1.1" in report
    assert "User: admin" in report
    assert "Time: 01:00" in report
    assert "5.5.5.5" in report

def test_generate_summary_report_empty():
    report = generate_summary_report({})
    assert report.strip() == "No threats found."

def test_format_threat_details_dict_entries():
    threats = [{"ip": "192.168.1.1", "username": "bob", "timestamp": "03:00"}]
    result = format_threat_details("failed_logins", threats)
    assert "IP: 192.168.1.1" in result
    assert "User: bob" in result
    assert "Time: 03:00" in result

def test_format_threat_details_list_entries():
    threats = ["192.0.2.1", "198.51.100.2"]
    result = format_threat_details("suspicious_ips", threats)
    assert "192.0.2.1" in result
    assert "198.51.100.2" in result

def test_format_threat_details_empty():
    result = format_threat_details("unknown", [])
    assert "No details available for unknown threats." in result

def test_save_report_success(tmp_path):
    report = "Sample report"
    file_path = tmp_path / "report.txt"
    success = save_report(report, str(file_path))
    assert success
    assert file_path.read_text() == "Sample report"

def test_save_report_permission_denied(monkeypatch):
    def mock_open_fail(*args, **kwargs):
        raise PermissionError("Permission denied")
    monkeypatch.setattr("builtins.open", mock_open_fail)
    result = save_report("report", "fakepath.txt")
    assert result is False

def test_display_report_print(capsys):
    display_report("Security Report")
    captured = capsys.readouterr()
    assert "Security Report" in captured.out

def test_display_report_empty(capsys):
    display_report("")
    captured = capsys.readouterr()
    assert "The report is empty." in captured.out

# ----------------------------
# Tests for main.py (CLI)
# ----------------------------

def test_parse_arguments_valid(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "auth.log", "-t", "5", "-i", "8.8.8.8", "-o", "output.txt"])
    args = parse_arguments()
    assert args.log_file == "auth.log"
    assert args.threshold == 5
    assert args.suspicious_ips == "8.8.8.8"
    assert args.output == "output.txt"

def test_parse_arguments_missing_required(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py"])
    with pytest.raises(SystemExit):
        parse_arguments()
