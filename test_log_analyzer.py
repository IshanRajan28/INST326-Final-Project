import pytest
from unittest.mock import patch, mock_open
from datetime import datetime
from log_analyzer import LogAnalyzer
import os

SAMPLE_LOGS = [
    '2023-01-01 00:15:30 192.168.1.1 user1 login failure',
    '2023-01-01 01:20:45 192.168.1.1 user1 login failure',
    '2023-01-01 02:30:15 10.0.0.1 admin login failure'
]

class TestThreatDetection:
    """Test suite for threat detection methods."""
    
    @pytest.fixture
    def populated_analyzer(self):
        """Fixture returning analyzer with parsed sample logs."""
        with patch('os.path.isfile', return_value=True):
            analyzer = LogAnalyzer('test.log')
        analyzer.parsed_logs = [
            {
                'timestamp': datetime(2023,1,1,0,15,30),
                'ip': '192.168.1.1',
                'username': 'user1',
                'action_status': ('login', 'failure'),
                'raw_line': SAMPLE_LOGS[0]
            },
            {
                'timestamp': datetime(2023,1,1,1,20,45),
                'ip': '192.168.1.1',
                'username': 'user1',
                'action_status': ('login', 'failure'),
                'raw_line': SAMPLE_LOGS[1]
            },
            {
                'timestamp': datetime(2023,1,1,2,30,15),
                'ip': '10.0.0.1',
                'username': 'admin',
                'action_status': ('login', 'failure'),
                'raw_line': SAMPLE_LOGS[2]
            }
        ]
        return analyzer
    
    def test_detect_failed_logins(self, populated_analyzer):
        """Should detect failed login attempts."""
        populated_analyzer.threshold = 2
        threats = populated_analyzer.detect_failed_logins()
        assert len(threats) == 2
        assert {'ip': '192.168.1.1', 'failed_attempts': 2} in threats
        assert {'username': 'user1', 'failed_attempts': 2} in threats

class TestReportGeneration:
    """Test suite for report generation."""
    
    @patch('os.path.isfile', return_value=True)
    @patch('log_analyzer.display_report')
    @patch('log_analyzer.generate_summary_report')
    def test_generate_report_to_console(self, mock_generate, mock_display, mock_isfile):
        """Should generate and display report when no output file given."""
        with patch('os.path.isfile', return_value=True):
            analyzer = LogAnalyzer('test.log')
        
        analyzer.parsed_logs = [
            {
                'timestamp': datetime(2023,1,1,0,15,30),
                'ip': '192.168.1.1',
                'action_status': ('login', 'success'),
                'raw_line': '2023-01-01 00:15:30 192.168.1.1 user1 login success'
            }
        ]
        
        mock_generate.return_value = "Test Report"
        result = analyzer.generate_report()
        mock_display.assert_called_once_with("Test Report")
        assert result == "Test Report"