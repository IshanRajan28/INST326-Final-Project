"""
Parses log files from SSH, Nginx, and Apache server logs to extract structured 
data.

This module provides utility functions to identify log formats and extract 
useful information such as timestamps, IP addresses, usernames, and action 
statuses. The parsed output is designed to support the functionality of 
log_analyzer.py, enabling security analysis and pattern detection.

Supported log formats:
- SSH auth logs (e.g., /var/log/auth.log)
- Apache access logs
- Nginx access logs
"""

from datetime import datetime
import re

def identify_log_format_from_sample(sample_line):
    """
    Identify the format of a log file from a sample line.
    
    Args:
        sample_line (str): A sample line from the log file
    
    Returns:
        str: Identified format type (files that end with .log like 'apache',
        'nginx', 'ssh')
    """
    
    # Check for Apache log format using regex pattern
    if re.search(r'\d+\.\d+\.\d+\.\d+ - - \[.*?\] ".*?" \d+ \d+', sample_line):
        return 'Apache'
    
    # Check for Nginx log format with another regex pattern
    elif re.search(r'^\d{1,3}(?:\.\d{1,3}){3} - \S+ \[[^\]]+\] ".*?" \d{3} \d+'
                   , sample_line):
        return 'Nginx'
    
    # Check if the line contains 'sshd' indicating an SSH log
    elif 'sshd' in sample_line:
        return 'ssh'
    
    # Return 'unknown' if the format doesn't match any known patterns
    else:
        return 'unknown'
    
    # Planned Tests:
    # Test with Apache log format
    # Test with Nginx log format
    # Test with SSH log format
    # Test with unknown log format

  
def parse_single_log_line(line, format_type =None):
    """
    Parse a single line from a log file into a structured format.
    
    Args:
        line (str): Log line to parse
        format_type (str, optional): Log format type, if None will attempt to indentify
    
    Returns:
        dict: Parsed log entry as a dictionary
    
    Raises:
        FileNotFoundError: If the log doesn't exist
    """
    if format_type is None:
        format_type = identify_log_format_from_sample(line)
    
    parsed = {
        'timestamp': extract_timestamp(line),
        'ip': extract_ip_address(line),
        'username': extract_username(line),
        'action_status': extract_action_status(line),
        'format': format_type,
        'raw_line': line.strip()
    }
    return parsed
    
    # Planned Tests:
    # Test with file containing multiple valid log lines
    # Test with file containing mixed valid and invalid lines
    # Test with non-existent file path

def extract_timestamp(log_line):
    """
    Extract the timestamp from a log line and convert to standard format.
    
    Args:
        log_line (str): Log line to extract timestamp from
    
    Returns:
        datetime or str: Standardized timestamp in the format '%Y-%m-%d %H:%M:%S', 
        or None if the timestamp cannot be parsed.
    
    Raises:
        ValueError: If the timestamp is in an invalid format.
    """
    patterns = [
        # Match Apache/Nginx log timestamps like [10/Oct/2023:13:55:36 +0000]
        r"\[(\d{2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]",
        # SSH log timestamps, e.g., Oct 10 13:55:36
        r'^([A-Za-z]{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log_line)
        if match:
            time_stamp = match.group(1)
            try:
                
                # For Apache/Nginx logs, which include data, time, and timezone
                if '/' in time_stamp:
                    dt = datetime.strptime(time_stamp, '%d/%b/%Y:%H:%M:%S %z')
                
                # For SSH logs, which only include month, day, and time
                else:
                    dt = datetime.strptime(time_stamp, '%b %d %H:%M:%S')
                    dt = dt.replace(year=datetime.now().year)
                
                # Return standardized datetime string
                return dt.strftime('%Y-%m-%d %H:%M:%S') 
            
            # Handle the specific exception
            except ValueError as e:
                raise ValueError(f"Invalid timestamp format in log line: {log_line}") from e
                
    # Return None if no valid timestamp is found
    print(f"Could not parse time script: {log_line}")
    return None
    # Planned Tests:
    # Test with standard timestamp format
    # Test with alternative timestamp formats
    # Test with timestamp including timezone
    # Test with log line missing timestamp


def extract_ip_address(log_line):
    """
    Extract IP address from a log line.
    
    Args:
        log_line (str): Log line to extract IP from
    
    Returns:
        str: Extracted IP address or None if not found
    """
    # Match IPv4 address pattern in the log line
    match = re.search(r'((?:\d{1,3}\.){3}\d{1,3})', log_line)
    if match:
        # Return matched IP address
        return match.group(1)
    else:
        # Return None if no IP address is found
        return None
    # Planned Tests:
    # Test extracting IPv4 address
    # Test with log line missing IP address


def extract_username(log_line):
    """
    Extract username from standard log formats (Apache, Nginx, SSH).
    Returns None if no valid username found.
    
    Handles these formats:
    - SSH: "Failed passwords for invalid user bob from 10.0.0.1"
    - Nginx: "127.0.0.1 - alice [10/Oct/2023:13:56:36 +0000]"
    - Apache "192.168.1.1 - frank [10/Oct/2023:13:55:36 +0000]"
    - Key-value: "user=admin" or "useradmin: admin"
    
    Args:
        log_line (str): Log line to extract username from
    
    Returns:
        str: Extracted username or None if not found
    """
    
    # For SSH logs, extract username after 'invalid user' or 'for'
    if (ssh_match := re.search(r'for (?:invalid user )?(\S+)', log_line)):
        return ssh_match.group(1)
    
    # For Apache/Nginx logs, extract username (if present) from log line
    if (web_match := re.search(r'^\S+ \S+ (\S+)(?= \[)', log_line)):
        if web_match.group(1) != '-':
            return web_match.group(1)
    
    # For key-value pairs like 'user=admin' in logs
    if (kv_match := re.search(r'user(?:name)?[=:]"?([^\s"\]]+)'
                              , log_line, re.IGNORECASE)):
        return kv_match.group(1)
    
    # Return 'N/A' if no username found
    return "N/A"


def extract_action_status(log_line):
    """
    Extract the action performed and its status from a log line.
    
    Args:
        log_line (str): Log line to extract action and status from
    
    Returns:
        tuple: (action, status) tuple or (None, None) if not found
    """
    # If the log line indicates a successful login
    if 'Accepted password' in log_line:
        return ('login', 'success')
    
    # If the log line indicates a failed login attempt
    elif 'Failed password' in log_line:
        return ('login', 'failure')
    
    # For web logs (GET/POST requests), extract the action and status based on 
    # response code
    elif 'GET' in log_line or 'POST' in log_line:
        match = re.search(r'"(GET|POST) .*?" (\d+)', log_line)
        if match:
            # Success if the status code starts with '2' (e.g., 200, 201)
            status = 'success' if match.group(2).startswith('2') else 'failure'
            return match.group(1).lower(), status
    
    # Return (None, None) if no recognizable action/status found
    return (None, None)
    # Planned Tests:
    # Test extracting login success action/status
    # Test extracting login failure action/status
    # Test extracting file access action/status
    # Test with log line having no clear action/status