from log_parser import parse_single_log_line
from report_generator import generate_summary_report
from API import get_malicious_ips, HISTORICAL_IPS
from collections import defaultdict
import os
from datetime import datetime
import re

class LogAnalyzer:
    """
    Main class for analzying security logs to detect potential threats.
    
    This class handles the coordination of parsing log files, running threat
    detection algorithms, and generating reports on the findings.
    
    Attributes:
        log_file_path (str): Path to the log file to analyze.
        suspicious_ip_list (list of str): Known malicious IPs to monitor. 
        Defaults to a predefined list.
        threshold (int): Minimum number of failed logins to trigger detection. 
        Defaults to 3.
        start_time (int): Start hour (24-hour format) for unusual activity detection. 
        Defaults to 23.
        end_time (int): End hour (24-hour format) for unusual activity detection. 
        Defaults to 5.
        parsed_logs (list of dict): Stores parsed log entries. 
        Populated after calling `parse_log_file()`.
    """
    
    def __init__(self, log_file_path, threshold = 3, suspicious_ip_list = None, 
                start_time = 23, end_time = 5, threat_api_key=None):
        """
        Initialize the LogAnalyzer with a path to the log file.
        
        Args:
            log_file_path (str): Path to the log file to be analyzed
        """
        if not os.path.isfile(log_file_path):
            raise FileNotFoundError(f"The log file at {log_file_path} does not exist.")
        
        self.log_file_path = log_file_path
        self.parsed_logs = []
        self.threshold = threshold
        
        if start_time < 0 or start_time > 23:
            raise ValueError(f"Invalid start time: {start_time}. Please enter a " 
                            "value between 0 and 23.")
        
        if end_time < 0 or end_time > 23:
            raise ValueError(f"Invalid end time: {end_time}. Please enter a value between " 
                            "0 and 23.")
    
        self.start_time = start_time
        self.end_time = end_time
        
       
        if suspicious_ip_list is None:
            if threat_api_key:
                self.suspicious_ip_list = get_malicious_ips(threat_api_key)
            
            else:
                self.suspicious_ip_list = HISTORICAL_IPS        
        else:
            self.suspicious_ip_list = suspicious_ip_list
        
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
        
        Side effects:
            Updates self.parsed_logs with parsed entries.
        """
        
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    parsed_entry = parse_single_log_line(line)
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
        
        This method orchestrates the execution of all individual threat.
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
        
    def detect_failed_logins(self):
        """
        Detects multiple failed login attempts from the same IP or username.
        
        Returns:
            list of dict: Each dict contains:
            - 'ip' (str): The source IP address.
            - 'username' (str): The attempted username.
            - 'failed_attempts' (int): Number of failed tries.
        """
        #Tracks {(ip, user): attempt_count}
        groups = defaultdict(int)
    
        for entry in self.parsed_logs:
            action, status = entry.get('action_status', (None, None))
            if action == 'login' and status == 'failure':
                ip = entry.get('ip')
                user = entry.get('username', 'invalid_user')
                groups[(ip, user)] += 1
        
        threats = []
        for (ip, user), count in groups.items():
            if count >= self.threshold:
                threats.append({
                    'ip': ip,
                    'username': user,
                    'failed_attempts': count
                })
        return threats
        # Planned Tests:
        # Test with exactly threshold failed attempts (should be detected)
        # Test with more than threshold failed attempts (should be detected)
        # Test with fewer than threshold attempts (should not be detected)
        # Test with customized threshold value

    def detect_suspicious_ips(self):
        """
        Identifies access from known suspicious IPs.
        
        Returns:
            list of dict: Each dict contains:
                - 'ip' (str): The suspicious IP.
                - 'count' (int): Number of matches.
                - 'entries' (list of dict): Raw log entries.
        """
        
        if not self.suspicious_ip_list:
            return []
        
        detected_threats = []
        
        for ip in self.suspicious_ip_list:
            matching_entries = []
            
            for entry in self.parsed_logs:
                if entry['ip'] == ip:
                    matching_entries.append(entry)
            
            if matching_entries:
                detected_threats.append({
                    'ip': ip,
                    'count': len(matching_entries),
                    'entries': matching_entries
                })
        
        return detected_threats

        # Planned Tests:
        # Test with provided list of suspicious IPs
        # Test with default suspicious IP list
        # Test with empty suspicious IP list
        # Test with IPs not in the suspicious list

    def detect_unusual_access_times(self):
        """
        Detects logins during unusual hours.
        
        Returns:
            list: Detected threats during unusual hours
        
        Raises:
            ValueError: No parsed logs found. Make sure to run 
            parse_log_file() first.
        """
        if not self.parsed_logs:
            raise ValueError("No parsed logs found. Make sure to run parse_log_file() " 
                             "first.")

        unusual_entries = []
        for entry in self.parsed_logs:
            timestamp = entry.get('timestamp')
            if not timestamp:
                continue
            
            timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            hour = timestamp.hour 
            
            if self.start_time > self.end_time:
                if hour >= self.start_time or hour < self.end_time:
                    unusual_entries.append(entry)

            else:
                if self.start_time <= hour < self.end_time:
                    unusual_entries.append(entry)
        
        return unusual_entries
            
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
        
        # common privilege escalation indicators
        escalation_keywords = ['sudo', 'su', 'root', 'uid=0']
        escalations = []
        
        for i, entry in enumerate(self.parsed_logs):
            if entry.get('action_status') is None:
                continue
            
            raw_line = entry.get('raw_line', '')
            
            keyword_found = False
            for keyword in escalation_keywords:
                if keyword in raw_line:
                    keyword_found = True
                    break
            if not keyword_found:
                continue
            
            source_user = entry.get('username', 'N/A')
            if 'sudo:' in raw_line:
                sudo_match = re.search(r'sudo:\s+([^\s]+)\s+:', raw_line)
                if sudo_match:
                    source_user = sudo_match.group(1)
            
            target_user = 'root'
            if 'sudo' in raw_line:
                target_match = re.search(r'USER=([^\s]+)', raw_line)
                if target_match:
                    target_user = target_match.group(1) 
            elif 'su' in raw_line:
                su_match = re.search(r'session opened for user ([^\s]+)', raw_line)
                if su_match:
                    target_user = su_match.group(1)
            
            ip = 'N/A'
            for prev_entry in reversed(self.parsed_logs[:i]):
                if prev_entry.get('username') == source_user and prev_entry.get('ip'):
                    ip = prev_entry['ip']
                    break
                
            command = 'unknown'
            if 'sudo' in raw_line:
                command_match = re.search(r'COMMAND=([^\s]+)', raw_line)
                command = command_match.group(1) if command_match else command
                
            escalations.append({
                'source_ip': ip,
                'source_user': source_user,
                'target_user': target_user,
                'command': command,
                'timestamp': entry.get('timestamp')
            })
        return escalations
                    
        # Planned Tests:
        # Test with clear privilege escalation patterns
        # Test with ambiguous privilege change patterns
        # Test with no privilege escalation attempts

    def generate_report(self):
        """
        Generate a formatted report of detected threats.
        
        Uses the report_generator module to create a summary report and returns
        the summary report.
            
        Returns:
            str: The generated report text
        """
        threats = self.detect_threats()
        
        report = generate_summary_report(threats)
        
        return report
        # Planned Tests:
        # Test generating report to console output
        # Test generating report to file
        # Test report generation with no detected threats
        # Test report formatting with various threat types