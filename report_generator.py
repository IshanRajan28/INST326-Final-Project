
def generate_summary_report(threats_summary):
    """
    Create a summary report based on threat detection findings.
    
    Args:
        threats_summary (dict): Dictionary of threats by category
    
    Returns:
        str: Formatted report text
    """
    # Planned Tests:
    # Test with multiple types of threats
    # Test with single type of threat
    # Test with empty threats dictionary

    if not threats_summary:
        return "No threats found.\n"

    report = "Threat Report\n-------------\n"
    for threat_type, threats in threats_summary.items():
        report += f"\n{threat_type.title()}: {len(threats)} found\n"
        if threats:
            report += format_threat_details(threat_type, threats) + "\n"
    return report

def format_threat_details(threat_type, threats):
    """
    Format detailed information for a specific threat type.
    
    Args:
        threat_type (str): Type of threat (e.g, 'failed_logins')
        threats (list): List of threats of this type
    
    Returns:
        str: Formatted threat details
    """
    # Planned Tests:
    # Test formatting failed login threats
    # Test formatting suspicious IP threats
    # Test formatting unusual access time threats
    # Test formatting privilege escalation threats
    # Test with unknown threat type

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
            lines.append(" | ".join(line))
        else:
            lines.append(str(threat))
    return "\n".join(lines)

def save_report(report, output_file_path):
    """
    Save a generated report to a file.
    
    Args:
        report (str): The report content
        output_file_path (str): Path were to save the report
    
    Returns:
        bool: True if successful, False otherwise
    """
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
    # Planned Tests:
    # Test displaying regular report
    # Test displaying report with ANSI color formatting
    # Test displaying empty report