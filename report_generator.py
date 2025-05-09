import os

def generate_summary_report(threats_summary):
    """
    Create a summary report based on threat detection findings.
    
    Args:
        threats_summary (dict): Dictionary of threats by category
    
    Returns:
        str: Formatted report text
    """

    if not threats_summary:
        return "No threats found.\n"

    report = "Threat Report\n-------------\n"
    for threat_type, threats in threats_summary.items():
        report += f"\n{threat_type.title()}: {len(threats)} found\n"
        if threats:
            report += format_threat_details(threat_type, threats) + "\n"
    return report

  
# Planned Tests:
# Test with multiple types of threats
# Test with single type of threat
# Test with empty threats dictionary

def format_threat_details(threat_type, threats):
    """
    Format detailed information for a specific threat type.
    
    Args:
        threat_type (str): Type of threat (e.g, 'failed_logins')
        threats (list): List of threats of this type
    
    Returns:
        str: Formatted threat details
    """
    
    if threat_type == 'privilege_escalation':
        lines = []
        for threat in threats:
            parts = [
                f"From: {threat.get('source_user', 'unknown')}"
                f"→{threat.get('target_user', 'root')}",
                f"IP: {threat.get('source_ip', 'unknown')}",
                f"Command: {threat.get('command', 'unknown')}",
                f"Time: {threat.get('timestamp', 'unknown')}"
            ]
            lines.append(" | ".join(parts))
        lines.append("\nRecommendation: Monitor privilege escalation events for " 
                    "unauthorized access.")
        return "\n".join(lines)

    elif threat_type == 'failed_logins':
        lines = []
        for threat in threats:
            if isinstance(threat, dict):
                line = []
                if "ip" in threat:
                    line.append(f"IP: {threat['ip']}")
                if "username" in threat:
                    line.append(f"User: {threat['username']}")
                if "failed_attempts" in threat:
                    line.append(f"Attempts: {threat['failed_attempts']}")
                if "timestamp" in threat:
                    line.append(f"Time: {threat['timestamp']}")
                if line:
                    lines.append(" | ".join(line))
        lines.append("\nRecommendation: Review failed login attempts for potential "
                    "brute-force attacks.")
        return "\n".join(lines)
    
    elif threat_type == 'suspicious_ips':
        lines = []
        for item in threats:
            ip = item['ip'] if isinstance(item, dict) else item
            lines.append(f"IP: {ip}")
        lines.append("\nRecommendation: Investigate activity from known malicious IP "
                    "addresses.")
        return "\n".join(lines)
    
    elif threat_type == 'unusual_access_times':
        lines = []
        for threat in threats:
            line = []
            if "ip" in threat:
                line.append(f"IP: {threat['ip']}")
            if "username" in threat:
                line.append(f"User: {threat['username']}")
            if "timestamp" in threat:
                line.append(f"Time: {threat['timestamp']}")
            if line:
                lines.append(" | ".join(line))
        lines.append("\nRecommendation: Investigate user activity during unusual hours" 
                    "for potential compromise.")
        return "\n".join(lines)
    
    else:
        lines = []
        for threat in threats:
            if isinstance(threat, dict):
                line = []
                if "ip" in threat:
                    line.append(f"IP: {threat['ip']}")
                if "username" in threat:
                    line.append(f"User: {threat['username']}")
                if "timestamp" in threat:
                    line.append(f"Time: {threat['timestamp']}")
                if line:
                    lines.append(" | ".join(line))
            else:
                lines.append(str(threat))
        
    if lines:
        return "\n".join(lines)
    else:
        return f"No details available for {threat_type} threats."


# Planned Tests:
# Test formatting failed login threats
# Test formatting suspicious IP threats
# Test formatting unusual access time threats
# Test formatting privilege escalation threats
# Test with unknown threat type

def save_report(report, output_file_path):
    """
    Save a generated report to a file.
    
    Args:
        report (str): The report content
        output_file_path (str): Path were to save the report
    
    Returns:
        bool: True if successful, False otherwise
    """

    try:
        with open(output_file_path, "w", encoding="utf-8") as file:
            file.write(report)
            file.flush()
            os.fsync(file.fileno()) 
        return True
    
    except PermissionError:
        print(f"ERROR: Permission denied when writing to {output_file_path}")
        return False
    
    except Exception as e:
        return False

  
# Planned Tests:
# Test saving to valid file path
# Test saving with permission issues
# Test saving empty report

def display_report(report):
    """
    Display a report to the console with appropriate formatting.
    
    Args:
        report (str): The report content
    """
    
    if report:
        print(report)
    else:
        print("The report is empty.")

  
# Planned Tests:
# Test displaying regular report
# Test displaying report with ANSI color formatting
# Test displaying empty report
