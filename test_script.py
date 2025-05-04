import pytest
from log_analyzer import LogAnalyzer
import log_parser
import report_generator

# Fixtures for setup
@pytest.fixture
def sample_log_file(sample_path):
    # Create and return a sample log file for testing
    content = (
        "2025-05-04 12:00:00 LOGIN SUCCESS user1 192.168.1.1\n"
        "2025-05-04 12:01:00 LOGIN FAILED user2 192.168.1.2\n"
        "2025-05-04 03:00:00 LOGIN SUCCESS user3 10.0.0.5"
    )
    file = sample_path / "sample.log"
    file.write_text(content)
    return str(file)

#LogAnalyzer tests
def test_initialization_with_valid_file(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    assert analyzer.log_file == sample_log_file

def test_initialization_with_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        LogAnalyzer("nonexistent.log")

def test_parse_log_file(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    assert len(analyzer.parsed_logs) == 3

def test_detect_threats(sample_log_file, mocker):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    mocker.patch.object(analyzer, 'detect_failed_logins', return_value=["fail"])
    mocker.patch.object(analyzer, 'detect_suspicious_ips', return_value=["ip"])
    mocker.patch.object(analyzer, 'detect_unusual_times', return_value=["time"])
    threats = analyzer.run_analysis()
    assert "Failed Logins" in threats
    assert "Suspicious IPs" in threats
    assert "Unusual Access Times" in threats

def test_detect_failed_logins_with_threshold(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    result = analyzer.detect_failed_logins(threshold=1)
    assert any("FAILED" in r for r in result)

def test_detect_suspicious_ips(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    result = analyzer.detect_suspicious_ips(["192.168.1."])
    assert result

def test_detect_unusual_times(sample_log_file):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    result = analyzer.detect_unusual_times(0, 6)
    assert result

def test_generate_report_to_console(sample_log_file, capsys):
    analyzer = LogAnalyzer(sample_log_file)
    analyzer.parse_log_file()
    threats = analyzer.run_analysis()
    report = analyzer.generate_report(threats)
    print(report)
    captured = capsys.readouterr()
    assert "Threat Report" in captured.out

#LogParser tests
def test_indentify_log_format():
    line = "2025-05-01 12:00:00 LOGIN SUCCESS user1 192.168.1.1"
    assert log_parser.identify_log_format(line) == "standard"

def test_parse_log_line():
    line = "2025-05-01 12:00:00 LOGIN SUCCESS user1 192.168.1.1"
    result = log_parser.parse_log_line(line)
    assert result["ip"] == "192.168.1.1"

def test_extract_ip_address():
    line = "LOGIN FAILED user2 192.168.1.2"
    assert log_parser.extract_ip_address(line) == "192.168.1.2"

#ReportGenerator tests
def test_generate_summary_report():
    summary = {"Failed Logins": ["example"]}
    report = report_generator.generate_summary_report(summary)
    assert "example" in report

def test_save_report(tmp_path):
    report = "Sample Report"
    file = tmp_path / "report.txt"
    report_generator.save_report(report, str(file))
    assert file.read_text() == report