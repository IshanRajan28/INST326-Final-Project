# Log File Analyzer

A Python command line tool that scans server logs to detect potential security threats such as failed login attempts, suspicious IPs, and unusual access patterns. Built at the University of Maryland for INST326.

## Repository Structure

INST326-Final-Project/

* main.py - Handles command-line arguments, coordinates the log analysis process, and manages how the results are displayed or saved

* log_analyzer.py - Main class for log analysis

* log_parser.py - Handles parsing of log files and extracting data

* report_generator.py - Formats and outputs threat reports

* test_log_analyzer.py - Unit tests for the analyzer

* test_log_parser.py - Unit tests for the parser

* test_report_generator.py - Unit tests for the reporter

* sample_log.txt - Example input log file

* README.md - This file

## Features

* Detects failed login attempts and brute force patterns

* Flags suspicious IP addresses

* Identifies access during unusual hours

* Generates clean and readable threat reports

* Modular code structure for easy testing and extension

## How It Works

Parse Logs: Extract IP addresses, timestamps, and login info.

Detect Threats: Apply logic and regex to find unusual activity.

Generate Report: Summarize threats into a readable format (console or file).

## How to Use the Program (with sample log file as example)

* Make sure files are located in the same directory.

```python
   python main.py apache_access.log
   ```
### Results
```python
   Threat Report
   -------------

   Failed_Logins: 0 found

   Suspicious_Ips: 0 found

   Unusual_Access_Times: 0 found

   Privilege_Escalation: 0 found
   ```

## Running Tests

pytest test_log_analyzer.py

pytest test_log_parser.py

pytest test_report_generator.py

### Manual Test: Report Generation
1. **Setup**: Run the analyzer on a sample log file:
   ```python
   analyzer = LogAnalyzer("sample.log")
   analyzer.parse_log_file()
   report = analyzer.generate_report("output.txt")
   ```
2. **Verify**:  
   - Open `output.txt` and check:  
     - Header contains "Threat Report".  
     - Correct number of threats listed.  
     - Formatting is clean.  

## Dependencies

Python 3.13.3

pytest (for testing)

## Team Members

Ishan Rajan

Evan Geisner

## Status

Core functionality complete
