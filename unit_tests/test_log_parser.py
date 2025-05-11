"""
Log Parser Unit Tests

Validates parsing of:
- Standard log formats (Apache/Nginx/SSH)
- Field extraction (timestamps, IPs, usernames)
- Edge cases (missing data, invalid formats)
"""

import pytest
from datetime import datetime
from log_parser import (
    identify_log_format_from_sample,
    parse_single_log_line,
    extract_timestamp,
    extract_ip_address,
    extract_username,
    extract_action_status
)

# Sample log lines for testing
APACHE_LOG = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234'
NGINX_LOG = '127.0.0.1 - alice [10/Oct/2023:13:56:36 +0000] "GET / HTTP/1.1" 200 1234'
SSH_LOG = 'Oct 10 13:55:36 server sshd[1234]: Failed password for invalid user bob from 10.0.0.1'
UNKNOWN_LOG = 'This is an unknown log format'

# Test identify_log_format_from_sample
@pytest.mark.parametrize("line, expected", [
    (APACHE_LOG, 'Apache'),
    (NGINX_LOG, 'Nginx'),
    (SSH_LOG, 'ssh'),
    (UNKNOWN_LOG, 'unknown'),
])
def test_identify_log_format_from_sample(line, expected):
    assert identify_log_format_from_sample(line) == expected

# Test extract_timestamp
@pytest.mark.parametrize("line, expected", [
    (APACHE_LOG, '2023-10-10 13:55:36'),
    (NGINX_LOG, '2023-10-10 13:56:36'),
    (SSH_LOG, f'{datetime.now().year}-10-10 13:55:36'),
    ("Line without timestamp", None),
])
def test_extract_timestamp(line, expected):
    if expected is None:
        assert extract_timestamp(line) is None
    else:
        assert extract_timestamp(line) == expected

# Test extract_ip_address
@pytest.mark.parametrize("line, expected", [
    (APACHE_LOG, '192.168.1.1'), 
    (NGINX_LOG, '127.0.0.1'),
    (SSH_LOG, '10.0.0.1'),
    ("Line without IP", None),
])
def test_extract_ip_address(line, expected):
    """Test IP extraction from various log formats
    Args:
        line: Raw log line input
        expected: Expected IP address or None if none should be found
    """
    assert extract_ip_address(line) == expected

# Test extract_username
@pytest.mark.parametrize("line, expected", [
    (APACHE_LOG, 'N/A'),
    (NGINX_LOG, 'alice'),
    (SSH_LOG, 'bob'),
    ("user=admin", 'admin'),
    ("Line without username", 'N/A'),
])
def test_extract_username(line, expected):
    assert extract_username(line) == expected

# Test extract_action_status
@pytest.mark.parametrize("line, expected", [
    (SSH_LOG, ('login', 'failure')),
    ("Accepted password for user", ('login', 'success')),
    ('"GET / HTTP/1.1" 200', ('get', 'success')),
    ('"POST /login HTTP/1.1" 404', ('post', 'failure')),
    ("Line without action", (None, None)),
])
def test_extract_action_status(line, expected):
    assert extract_action_status(line) == expected

# Test parse_single_log_line
def test_parse_single_log_line():
    """Test complete log line parsing with Nginx format
    - Verifies all extracted fields (format, IP, username, action)
    - Checks raw line preservation
    """
    result = parse_single_log_line(NGINX_LOG)
    assert result['format'] == 'Nginx'
    assert result['ip'] == '127.0.0.1'
    assert result['username'] == 'alice'
    assert result['action_status'] == ('get', 'success')
    assert 'raw_line' in result

def test_parse_single_log_line_unknown_format():
    result = parse_single_log_line(UNKNOWN_LOG)
    assert result['format'] == 'unknown'

def test_parse_single_log_line_with_forced_format():
    """Test parsing with explicit format override."""
    result = parse_single_log_line(SSH_LOG, format_type='ssh')
    assert result['format'] == 'ssh'
    assert result['username'] == 'bob'