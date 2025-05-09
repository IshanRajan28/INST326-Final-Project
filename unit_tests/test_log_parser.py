import pytest
from datetime import datetime
from log_parser import (
    identify_log_format,
    parse_log_line,
    extract_timestamp,
    extract_ip_address,
    extract_username,
    extract_action_status
)

# Test samples covering Apache, Nginx, SSH, and unknown formats
APACHE_LOG = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234'
NGINX_LOG = '127.0.0.1 - alice [10/Oct/2023:13:55:36 +0000] "POST /login HTTP/1.1" 201 567'
SSH_LOG = 'Oct 10 13:55:36 server sshd[12345]: Failed password for invalid user bob from 10.0.0.1 port 54321'
UNKNOWN_LOG = 'This is an unrecognized log format'

class TestIdentifyLogFormat:
    """Tests for identify_log_format()"""
    
    def test_identify_apache(self):
        # Verify Apache common log format detection
        assert identify_log_format(APACHE_LOG) == 'Apache'
    
    def test_identify_nginx(self):
        # Check Nginx variant format detection
        assert identify_log_format(NGINX_LOG) == 'Nginx'
    
    def test_identify_ssh(self):
        # Test SSH auth log identification
        assert identify_log_format(SSH_LOG) == 'ssh'
    
    def test_identify_unknown(self):
        # Confirm handling of unrecognized formats
        assert identify_log_format(UNKNOWN_LOG) == 'unknown'

class TestExtractTimestamp:
    """Tests for extract_timestamp()"""
    
    def test_extract_apache_timestamp(self):
        # Check Apache/Nginx timestamp parsing
        timestamp = extract_timestamp(APACHE_LOG)
        assert isinstance(timestamp, datetime)
        assert timestamp.year == 2023
        assert timestamp.month == 10
    
    def test_extract_ssh_timestamp(self):
        # Verify SSH abbreviated timestamp handling
        timestamp = extract_timestamp(SSH_LOG)
        assert isinstance(timestamp, datetime)
        assert timestamp.hour == 13
        assert timestamp.minute == 55
    
    def test_no_timestamp(self):
        # Test missing timestamp case
        assert extract_timestamp('No timestamp here') is None

class TestExtractIPAddress:
    """Tests for extract_ip_address()"""
    
    def test_extract_ipv4(self):
        # Verify IPv4 extraction from different formats
        assert extract_ip_address(APACHE_LOG) == '192.168.1.1'
        assert extract_ip_address(SSH_LOG) == '10.0.0.1'
    
    def test_no_ip(self):
        # Test log lines without IPs
        assert extract_ip_address('No IP in this string') is None

class TestExtractUsername:
    """Tests for extract_username()"""
    
    def test_extract_ssh_username(self):
        # Check SSH failed login username extraction
        assert extract_username(SSH_LOG) == 'bob'
    
    def test_extract_nginx_username(self):
        # Verify web server username parsing
        assert extract_username(NGINX_LOG) == 'alice'
    
    def test_no_username(self):
        # Test anonymous/missing username cases
        assert extract_username('No username here') is None

class TestExtractActionStatus:
    """Tests for extract_action_status()"""
    
    def test_ssh_failed_login(self):
        # Verify SSH auth failure detection
        assert extract_action_status(SSH_LOG) == ('login', 'failure')
    
    def test_apache_get_success(self):
        # Check HTTP GET success parsing
        assert extract_action_status(APACHE_LOG) == ('get', 'success')
    
    def test_nginx_post_success(self):
        # Test HTTP POST success detection
        assert extract_action_status(NGINX_LOG) == ('post', 'success')
    
    def test_no_action(self):
        # Verify non-action log handling
        assert extract_action_status('No action here') == (None, None)

class TestParseLogLine:
    """Tests for parse_log_line()"""
    
    def test_parse_apache_log(self):
        # Test complete Apache log parsing
        parsed = parse_log_line(APACHE_LOG)
        assert parsed['ip'] == '192.168.1.1'
        assert parsed['format'] == 'Apache'
        assert parsed['action_status'] == ('get', 'success')
    
    def test_parse_ssh_log(self):
        # Verify full SSH log parsing
        parsed = parse_log_line(SSH_LOG)
        assert parsed['username'] == 'bob'
        assert parsed['format'] == 'ssh'
        assert parsed['action_status'] == ('login', 'failure')
    
    def test_parse_with_explicit_format(self):
        # Test format override capability
        parsed = parse_log_line(SSH_LOG, format_type='ssh')
        assert parsed['format'] == 'ssh'
    
    def test_parse_malformed_log(self):
        # Verify error handling for invalid logs
        parsed = parse_log_line('garbage data')
        assert parsed['format'] == 'unknown'
        assert parsed['timestamp'] is None