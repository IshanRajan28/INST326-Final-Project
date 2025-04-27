from log_parser import parse_log_line
from report_generator import generate_summary_report, display_report, save_report
from collections import defaultdict
import os

class LogAnalyzer:
    """
    Main class for analzying security logs to detect potential threats
    
    This class handles the coordination of parsing log files, running threat
    detection algorithms, and generating reports on the findings.
    """
    
    def __init__(self, log_file_path):
        """
        Initialize the LogAnalyzer with a path to the log file.
        
        Args:
            log_file_path (str): Path to the log file to be analyzed
        """
        if not os.path.isfile(log_file_path):
            raise FileNotFoundError(f"The log file at {log_file_path} does not exist.")
        
        self.log_file_path = log_file_path
        self.parsed_logs = []
        # Planned Tests:
        # Test initialization with valid log file path
        # Test initialization with non-existent file (should raise FileNotFoundError)
        
    def parse_log_file(self):
        """
        Reads the log file and parses it using functions from log_parser.py.

        Returns:
            list: Parsed log entries as dictionaries
        
        Raises:
            FileNotFoundError: If the log file doesn't exist
            ValueError: If the log file format is invalid
        """
        self.parsed_logs = []
        
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    parsed_entry = parse_log_line(line)
                    if parsed_entry:
                        self.parsed_logs.append(parsed_entry)
        
        except Exception as e:
            raise ValueError(f"Error parsing log file: {e}")
        
        return self.parsed_logs
        # Planned Tests:
        # Test parsing a valid log file with multiple entries
        # Test parsing an empty log file
        # Test handling of malformed entries in the log file
    
    def detect_threats(self):
        """
        Master method that runs all threat detection algorithms and compiles results.
        
        This method orchestrates the execution of all individual threat
        detection methods and compiles their results.

        Returns:
            dict: Summary of all detected threats by category
        """
        threats_summary = {
            "failed_logins": self.detect_failed_logins(),
            "suspicious_ips": self.detect_suspicious_ips(),
            "unusual_access_times": self.detect_unusual_access_times(),
            "privilege_escalation": self.detect_privilege_escalation()
        }
        return threats_summary
        # Planned Tests:
        # Test with log data containing no threats
        # Test with log data containing multiple types of threats
        # Test that all detection methods are called and results are combined
        
    def detect_failed_logins(self, threshold=3):
        """
        Detects multiple failed login attempts from the same IP or username.
        
        Args:
            threshold (int): Number of failed attempts to trigger a detection
        
        Returns:
            list: Detected failed login threats
        """
        failed_attempts_by_ip = defaultdict(int)
        failed_attempts_by_username = defaultdict(int)
        detected_ips = set()
        detected_usernames = set()
        failed_logins = []
        
        for log_entry in self.parsed_logs:
            ip = log_entry.get('ip')
            username = log_entry.get('username')
            action, status = log_entry.get('action_status', (None, None))
            
            if action == 'login' and status == 'failure':
                if ip:
                    failed_attempts_by_ip[ip] += 1
                    if failed_attempts_by_ip[ip] >= threshold and ip not in detected_ips:
                        failed_logins.append({'ip': ip, 'failed_attempts': failed_attempts_by_ip[ip]})
                        detected_ips.add(ip)
                    
                    if username:
                        failed_attempts_by_username[username] += 1
                        if failed_attempts_by_username[username] >= threshold and username not in detected_usernames:
                            failed_logins.append({'username': username, 'failed_attempts': failed_attempts_by_username[username]})
                            detected_usernames.add(username)
        
        return failed_logins
        # Planned Tests:
        # Test with exactly threshold failed attempts (should be detected)
        # Test with more than threshold failed attempts (should be detected)
        # Test with fewer than threshold attempts (should not be detected)
        # Test with customized threshold value

    def detect_suspicious_ips(self, suspicious_ip_list=None):
        """
        Identifies access from known suspicious IPs.
        
        Args:
            suspicious_ip_list (list, optional): List of known supicious IPS
        
        Returns:
            list: Detected threats from suspicious IPs
        """
        pass
        # Planned Tests:
        # Test with provided list of suspicious IPs
        # Test with default suspicious IP list
        # Test with empty suspicious IP list
        # Test with IPs not in the suspicious list

    def detect_unusual_access_times(self, start_hour=23, end_hour=5):
        """
        Detects logins during unusual hours.
        
        Args:
            start_hour (int): Start hour for unusual time range (24-hour format)
            end_hour (int): End hour for unusual time range (24-hour format)
        
        Returns:
            list: Detected threats during unusual hours
        """
        pass
        # Planned Tests:
        # Test with access during default unusual hours
        # Test with access outside default unusual hours
        # Test with custom unusual hour range
        # Test with invalid hour values (e.g., hours > 24)

    def detect_privilege_escalation(self):
        """
        Identifies potential privilege escalation attempts.
        
        Looks for patterns indicating a user attempting to gain higher privileges
        than they should have access to.
        
        Returns:
            list: Detected privilege escalation threats
        """
        pass
        # Planned Tests:
        # Test with clear privilege escalation patterns
        # Test with ambiguous privilege change patterns
        # Test with no privilege escalation attempts

    def generate_report(self, output_file=None):
        """
        Generate a formatted report of detected threats.
        
        Uses the report_generator module to create a summary report and either
        display it to the console or save it to a file.

        Args:
            output_file (str, optional): Path to save the report, if None prints to console
            
        Returns:
            str: The generated report text
        """
        threats = self.detect_threats()
        report = generate_summary_report(threats)
        if output_file:
            save_report(report, output_file)
        else:
            display_report(report)
        return report
        # Planned Tests:
        # Test generating report to console output
        # Test generating report to file
        # Test report generation with no detected threats
        # Test report formatting with various threat types