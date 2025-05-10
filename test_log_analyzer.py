import pytest
import tempfile
import os
from log_analyzer import LogAnalyzer

# Sample parsed log entries for mocking
sample_logs = [
    {
        'timestamp': '2025-05-10 00:15:00',
        'ip': '192.168.1.10',
        'username': 'user1',
        'action_status': ('login', 'failure'),
        'raw_line': 'May 10 00:15:00 server sshd[12345]: Failed password for user1 from 192.168.1.10 port 22 ssh2'
    },
    {
        'timestamp': '2025-05-10 00:16:00',
        'ip': '192.168.1.10',
        'username': 'user1',
        'action_status': ('login', 'failure'),
        'raw_line': 'May 10 00:16:00 server sshd[12346]: Failed password for user1 from 192.168.1.10 port 22 ssh2'
    },
    {
        'timestamp': '2025-05-10 00:17:00',
        'ip': '192.168.1.10',
        'username': 'user1',
        'action_status': ('login', 'failure'),
        'raw_line': 'May 10 00:17:00 server sshd[12347]: Failed password for user1 from 192.168.1.10 port 22 ssh2'
    },
    {
        'timestamp': '2025-05-10 02:00:00',
        'ip': '45.227.225.6',
        'username': 'admin',
        'action_status': ('login', 'success'),
        'raw_line': 'May 10 02:00:00 server sshd[23456]: Accepted password for admin from 45.227.225.6 port 22 ssh2'
    },
    {
        'timestamp': '2025-05-10 01:00:00',
        'ip': '192.168.1.20',
        'username': 'root',
        'action_status': ('command', 'success'),
        'raw_line': 'May 10 01:00:00 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash'
    }
]

@pytest.fixture
def temp_log_file():
    """Creates a temporary log file with sample logs for testing.
    Ensures tests don't rely on external files and are isolated.
    """
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tf:
        tf.write("\n".join(entry['raw_line'] for entry in sample_logs))
        return tf.name

def test_init_valid_file(temp_log_file):
    """Test that LogAnalyzer initializes correctly with a valid log file.
    - Verifies the file path is stored.
    - Checks default threshold (3) is set.
    """
    analyzer = LogAnalyzer(temp_log_file)
    assert analyzer.log_file_path == temp_log_file
    assert analyzer.threshold == 3

def test_init_invalid_file():
    """Test that LogAnalyzer raises FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        LogAnalyzer("non_existent_file.log")

def test_parse_log_file(monkeypatch, temp_log_file):
    """Test log parsing with mocked parser.
    - Mocks parse_single_log_line to return sample entries.
    - Verifies all sample logs are parsed.
    """
    def mock_parse_single_log_line(line):
        for entry in sample_logs:
            if entry['raw_line'] in line:
                return entry
        return None

    monkeypatch.setattr("log_parser.parse_single_log_line", mock_parse_single_log_line)
    analyzer = LogAnalyzer(temp_log_file)
    parsed = analyzer.parse_log_file()
    assert len(parsed) == len(sample_logs)

def test_detect_failed_logins():
    """Test detection of failed logins meeting the threshold (default=3).
    - Setup: 3 failed logins from '192.168.1.10'.
    - Expected: 1 threat detected with 3 attempts.
    """
    analyzer = LogAnalyzer(__file__)
    analyzer.parsed_logs = sample_logs
    failed = analyzer.detect_failed_logins()
    assert len(failed) == 1
    assert failed[0]['failed_attempts'] == 3
    assert failed[0]['ip'] == '192.168.1.10'

def test_detect_failed_logins_below_threshold():
    """Test that failed logins below threshold are ignored.
    - Setup: 3 failed logins with threshold=5.
    - Expected: No threats detected.
    """
    analyzer = LogAnalyzer(__file__, threshold=5)
    analyzer.parsed_logs = sample_logs
    failed = analyzer.detect_failed_logins()
    assert len(failed) == 0

def test_detect_suspicious_ips():
    """Test detection of known suspicious IPs.
    - Setup: Sample logs include '45.227.225.6' (in default suspicious list).
    - Expected: The IP is flagged.
    """
    analyzer = LogAnalyzer(__file__)
    analyzer.parsed_logs = sample_logs
    threats = analyzer.detect_suspicious_ips()
    ips = [t['ip'] for t in threats]
    assert '45.227.225.6' in ips

def test_detect_unusual_access_times():
    """Test detection of logins during unusual hours (default: 23:00-05:00).
    - Setup: Sample logs include entries at 00:15-00:17 (within unusual range).
    - Expected: The entries are flagged.
    """
    analyzer = LogAnalyzer(__file__, start_time=23, end_time=5)
    analyzer.parsed_logs = sample_logs
    unusual = analyzer.detect_unusual_access_times()
    assert any(entry['timestamp'].startswith('2025-05-10 00') for entry in unusual)

def test_detect_privilege_escalation():
    """Test detection of privilege escalation via sudo.
    - Setup: Sample logs include a sudo command escalating to root.
    - Expected: 1 escalation detected (user1 -> root).
    """
    analyzer = LogAnalyzer(__file__)
    analyzer.parsed_logs = sample_logs
    priv = analyzer.detect_privilege_escalation()
    assert len(priv) == 1
    assert priv[0]['source_user'] == 'user1'
    assert priv[0]['target_user'] == 'root'
    assert priv[0]['command'] == '/bin/bash'


