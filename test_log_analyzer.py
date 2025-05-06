import pytest
from unittest.mock import patch, mock_open
from datetime import datetime
from log_analyzer import LogAnalyzer


# =============================================
# TEST DATA DEFINITIONS
# =============================================

# Valid log entries testing standard security scenarios:
# - 3 failed logins from same IP/user (should trigger threshold alerts)
# - 1 successful sudo command (should trigger privilege escalation check)
# - 1 failed login from known suspicious IP (should trigger IP detection)
SAMPLE_LOGS = [
    '2023-01-01 00:15:30 192.168.1.1 user1 login failure',  # First failure
    '2023-01-01 01:20:45 192.168.1.1 user1 login failure',  # Second failure 
    '2023-01-01 02:30:15 192.168.1.1 user1 login failure',  # Third failure (threshold reached)
    '2023-01-01 03:45:00 192.168.1.2 user2 sudo success',   # Privilege escalation pattern
    '2023-01-01 04:10:30 45.227.225.6 attacker login failure'  # Known suspicious IP
]

# Malformed log entries testing error handling:
# - Invalid IP format
# - Invalid timestamp
# - Incomplete log entry
MALFORMED_LOGS = [
    '2023-01-01 00:15:30 BAD_IP user1 login success',  # Invalid IP
    'INVALID TIMESTAMP 192.168.1.1 user1 login failure',  # Bad timestamp
    '2023-01-01 02:30:15 45.227.225.6 attacker'  # Missing action/status
]

# =============================================
# TEST SUITE: INITIALIZATION
# =============================================

class TestLogAnalyzerInitialization:
    """Verify LogAnalyzer constructor handles initialization correctly."""
    
    @patch('os.path.isfile', return_value=True)
    def test_init_with_valid_file(self, mock_isfile):
        """Should successfully initialize with valid file path and defaults."""
        analyzer = LogAnalyzer('valid.log')
        
        # Verify core attributes are set correctly
        assert analyzer.log_file_path == 'valid.log'
        assert analyzer.parsed_logs == []  # Should start empty
        assert analyzer.threshold == 3  # Default threshold
        
        # Verify file existence check was performed
        mock_isfile.assert_called_once_with('valid.log')
    
    @patch('os.path.isfile', return_value=False)
    def test_init_with_nonexistent_file(self, mock_isfile):
        """Should raise FileNotFoundError when log file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            LogAnalyzer('nonexistent.log')
            
        mock_isfile.assert_called_once_with('nonexistent.log')
    
    @patch('os.path.isfile', return_value=True)
    def test_init_with_custom_threshold(self, _):
        """Should accept and use custom failed login threshold."""
        analyzer = LogAnalyzer('valid.log', threshold=5)
        assert analyzer.threshold == 5  # Custom value should override default
    
    @patch('os.path.isfile', return_value=True)
    def test_init_with_custom_suspicious_ips(self, _):
        """Should accept and use custom suspicious IP list."""
        custom_ips = ['1.1.1.1', '2.2.2.2']
        analyzer = LogAnalyzer('valid.log', suspicious_ip_list=custom_ips)
        assert analyzer.suspicious_ip_list == custom_ips  # Should override default
    
    @patch('os.path.isfile', return_value=True)
    @pytest.mark.parametrize("start,end", [
        (-1, 5),   # Negative start hour
        (23, 24),  # End hour exceeds 23  
        (25, 5),   # Start hour exceeds 23
        (18, -5)   # Negative end hour
    ])
    def test_init_with_invalid_time_ranges(self, _, start, end):
        """Should reject invalid time ranges (hours outside 0-23)."""
        with pytest.raises(ValueError):
            LogAnalyzer('valid.log', start_time=start, end_time=end)

# =============================================
# TEST SUITE: LOG PARSING
# =============================================

class TestLogParsing:
    """Verify log file parsing handles various input scenarios."""
    
    @patch('os.path.isfile', return_value=True)
    @patch('builtins.open', mock_open(read_data='\n'.join(SAMPLE_LOGS)))
    def test_parse_valid_log_file(self, mock_isfile):
        """Should correctly parse well-formed log entries."""
        analyzer = LogAnalyzer('valid.log')
        parsed = analyzer.parse_log_file()
        
        # Should parse all lines into dictionaries
        assert len(parsed) == len(SAMPLE_LOGS)
        assert all(isinstance(entry, dict) for entry in parsed)  # All entries should be dicts
    
    @patch('os.path.isfile', return_value=True)
    @patch('builtins.open', mock_open(read_data=''))
    def test_parse_empty_file(self, mock_isfile):
        """Should handle empty log file without errors."""
        analyzer = LogAnalyzer('empty.log')
        parsed = analyzer.parse_log_file()
        assert parsed == []  # Should return empty list
    
    @patch('os.path.isfile', return_value=True)
    @patch('builtins.open', mock_open(read_data='\n'.join(MALFORMED_LOGS)))
    def test_parse_malformed_entries(self, mock_isfile):
        """Should mark malformed entries while continuing to parse."""
        analyzer = LogAnalyzer('malformed.log')
        parsed = analyzer.parse_log_file()
        
        # All lines should be processed, malformed ones marked
        assert len(parsed) == len(MALFORMED_LOGS)
        assert all(entry.get('format') == 'unknown' for entry in parsed)  # Malformed flag
    
    @patch('builtins.open', side_effect=PermissionError("Access denied"))
    @patch('os.path.isfile', return_value=True)
    def test_parse_with_file_permission_error(self, mock_isfile, _):
        """Should convert file access errors to ValueError with message."""
        analyzer = LogAnalyzer('restricted.log')
        with pytest.raises(ValueError, match="Error parsing log file"):
            analyzer.parse_log_file()

# =============================================
# TEST SUITE: THREAT DETECTION
# =============================================

class TestThreatDetection:
    """Verify threat detection algorithms identify security events correctly."""
    
    @pytest.fixture
    def populated_analyzer(self):
        """Fixture providing analyzer with pre-parsed sample logs."""
        with patch('os.path.isfile', return_value=True):
            analyzer = LogAnalyzer('test.log')
        
        # Set up realistic log scenarios:
        # - 3 failed logins (IP: 192.168.1.1, user: user1)
        # - 1 failed login from suspicious IP
        # - 1 successful sudo command
        analyzer.parsed_logs = [
            {'timestamp': datetime(2023,1,1,0,15,30), 'ip': '192.168.1.1', 'username': 'user1', 'action_status': ('login', 'failure'), 'raw_line': SAMPLE_LOGS[0]},
            {'timestamp': datetime(2023,1,1,1,20,45), 'ip': '192.168.1.1', 'username': 'user1', 'action_status': ('login', 'failure'), 'raw_line': SAMPLE_LOGS[1]},
            {'timestamp': datetime(2023,1,1,2,30,15), 'ip': '192.168.1.1', 'username': 'user1', 'action_status': ('login', 'failure'), 'raw_line': SAMPLE_LOGS[2]},
            {'timestamp': datetime(2023,1,1,3,45,0), 'ip': '45.227.225.6', 'username': 'attacker', 'action_status': ('login', 'failure'), 'raw_line': SAMPLE_LOGS[4]},
            {'timestamp': datetime(2023,1,1,4,10,30), 'ip': '192.168.1.2', 'username': 'user2', 'action_status': ('sudo', 'success'), 'raw_line': SAMPLE_LOGS[3]},
        ]
        return analyzer
    
    def test_detect_failed_logins_below_threshold(self, populated_analyzer):
        """Should ignore failures when below threshold."""
        populated_analyzer.threshold = 5  # Set threshold above actual failures (3)
        threats = populated_analyzer.detect_failed_logins()
        assert threats == []  # Should return empty list
    
    def test_detect_failed_logins_at_threshold(self, populated_analyzer):
        """Should detect when failures meet threshold."""
        populated_analyzer.threshold = 2  # Set threshold below actual failures (3)
        threats = populated_analyzer.detect_failed_logins()
        
        # Should return separate entries for IP and username
        assert len(threats) == 2
        
        # Verify IP threat details
        ip_threat = next((t for t in threats if 'ip' in t), None)
        assert ip_threat is not None
        assert ip_threat['ip'] == '192.168.1.1'
        assert ip_threat['failed_attempts'] == 3  # Should report actual count
        
        # Verify username threat details
        user_threat = next((t for t in threats if 'username' in t), None)
        assert user_threat is not None
        assert user_threat['username'] == 'user1'
        assert user_threat['failed_attempts'] == 3
    
    def test_detect_suspicious_ips(self, populated_analyzer):
        """Should flag activity from known suspicious IPs."""
        threats = populated_analyzer.detect_suspicious_ips()
        
        # Should detect the known suspicious IP (45.227.225.6)
        assert len(threats) == 1
        assert threats[0]['ip'] == '45.227.225.6'
    
    def test_detect_suspicious_ips_empty_list(self, populated_analyzer):
        """Should return empty list when no suspicious IPs configured."""
        populated_analyzer.suspicious_ip_list = []  # Clear default list
        threats = populated_analyzer.detect_suspicious_ips()
        assert threats == []
    
    @pytest.mark.parametrize("hour,expected", [
        (0, True),   # Midnight (in default 23-5 unusual range)
        (4, True),   # 4 AM (in range)
        (12, False), # Noon (normal hours)
        (23, True)   # 11 PM (in range)
    ])
    def test_detect_unusual_access_times(self, populated_analyzer, hour, expected):
        """Should identify access during configured unusual hours."""
        # Modify timestamp of first log entry
        populated_analyzer.parsed_logs[0]['timestamp'] = datetime(2023,1,1,hour,0,0)
        
        unusual = populated_analyzer.detect_unusual_access_times()
        assert (populated_analyzer.parsed_logs[0] in unusual) == expected
    
    def test_detect_privilege_escalation(self, populated_analyzer):
        """Should detect sudo/su/root privilege escalation patterns."""
        threats = populated_analyzer.detect_privilege_escalation()
        
        # Should flag the sudo command
        assert len(threats) == 1
        assert threats[0]['action_status'][0] == 'sudo'
    
    def test_detect_threats_integration(self, populated_analyzer):
        """Should combine all threat detection results."""
        threats = populated_analyzer.detect_threats()
        
        # Verify all detection methods were called
        assert isinstance(threats, dict)
        assert 'failed_logins' in threats
        assert 'suspicious_ips' in threats
        assert 'unusual_access_times' in threats
        assert 'privilege_escalation' in threats

# =============================================
# TEST SUITE: REPORT GENERATION
# =============================================

class TestReportGeneration:
    """Verify report generation handles console and file output."""
    
    @patch('os.path.isfile', return_value=True)
    @patch('log_analyzer.display_report')
    @patch('log_analyzer.generate_summary_report')
    def test_generate_report_to_console(self, mock_generate, mock_display, mock_isfile):
        """Should display report when no output file specified."""
        with patch('os.path.isfile', return_value=True):
            analyzer = LogAnalyzer('test.log')
        
        # Minimal log entry to trigger report generation
        analyzer.parsed_logs = [{
            'timestamp': datetime(2023,1,1,0,15,30),
            'ip': '192.168.1.1',
            'action_status': ('login', 'success'),
            'raw_line': 'sample log line'
        }]
        
        mock_generate.return_value = "Test Report"
        result = analyzer.generate_report()
        
        # Verify display function was called with report content
        mock_display.assert_called_once_with("Test Report")
        assert result == "Test Report"
    
    @patch('os.path.isfile', return_value=True)
    @patch('log_analyzer.save_report')
    @patch('log_analyzer.generate_summary_report')
    def test_generate_report_to_file(self, mock_generate, mock_save, mock_isfile):
        """Should save report to file when path specified."""
        with patch('os.path.isfile', return_value=True):
            analyzer = LogAnalyzer('test.log')
        
        analyzer.parsed_logs = [{
            'timestamp': datetime(2023,1,1,0,15,30),
            'ip': '192.168.1.1',
            'action_status': ('login', 'success'),
            'raw_line': 'sample log line'
        }]
        
        mock_generate.return_value = "Test Report"
        result = analyzer.generate_report('output.txt')
        
        # Verify save function was called with correct arguments
        mock_save.assert_called_once_with("Test Report", 'output.txt')
        assert result == "Test Report"