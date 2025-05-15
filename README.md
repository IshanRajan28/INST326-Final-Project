# Network File Log Detection System (NFLDS)

NFLDS is a Python command-line tool designed to scan server logs for potential security threats such as failed login attempts, suspicious IP addresses, and unusual access patterns. It helps security analysts detect brute-force attacks and unauthorized access. Built at the University of Maryland for INST326.

## Repository Structure

INST326-Final-Project/

* main.py - Handles command-line arguments, coordinates the log analysis process, and manages how the results are displayed or saved

* log_analyzer.py - Main class for log analysis

* log_parser.py - Handles parsing of log files and extracting data

* report_generator.py - Formats and outputs threat reports

* API.py - Runs the API that has access to current suspicious IPs

unit_tests

    * test_log_analyzer.py - Unit tests for the analyzer

    * test_log_parser.py - Unit tests for the parser

    * test_report_generator.py - Unit tests for the reporter

    * test_API.py - Unit tests for the API

log_testing folder

    * apache_access.log - Example Apache log file
    * sample_auth.log - Example SSH log file
    * ssh_auth.log - Example SSH log file

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

* Make sure API.py, log_analyzer.py, log_parser.py and main.py are located in the same directory.

```
   python main.py sample_auth.log
   ```

### Command Line Parameters

| Argument                  | Description                                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------------------- |
| `-o`, `--output`          | Path to save the output report. Example: `--output report.txt`                                      |
| `-t`, `--threshold`       | Threshold for failed login attempts (default: 3). Example: `--threshold 5`                          |
| `-i`, `--suspicious-ips`  | Comma-separated list of suspicious IPs. Example: `--suspicious-ips 192.168.1.15,10.0.0.5`           |
| `-s`, `--start-time`      | Start hour for detecting unusual access times (default: 23). Example: `--start-time 22`             |
| `-e`, `--end-time`        | End hour for detection

* You would get prompted with this if you didn't enter any suspicious-ips.
```
No AbuseIPDB API key provided.
You can:
1) Enter it now (will be used for this session only)
2) Press Enter to skip (limited threat detection)
Your choice [1/2]: 
```

* To get the AbuseIPDB API key, vist the link below

https://www.abuseipdb.com/api.html

Then go to User Account > API

Then create an API key

Don't share or show your API key to anyone 

The program also hides the input of the API key

* If you want to use your API key make sure to copy the API key from the website and input it when you get prompted.

* If you choose not to use your API and hit 2, and the program uses a generic suspicious ip list.

### Results (Without API key provided)
```
Threat Report
-------------

Failed_Logins: 1 found
IP: 192.168.1.101 | User: root | Attempts: 3

Recommendation: Review failed login attempts for potential brute-force attacks.

Suspicious_Ips: 1 found
IP: 185.232.67.3

Recommendation: Investigate activity from known malicious IP addresses.

Unusual_Access_Times: 4 found
IP: 10.0.0.1 | User: jim | Time: 2025-05-08 01:45:01
IP: None | User: root | Time: 2025-05-08 02:00:00
IP: 192.168.1.105 | User: user | Time: 2025-05-08 03:15:10
IP: None | User: root | Time: 2025-05-08 04:59:59

Recommendation: Investigate user activity during unusual hours for potential compromise.

Privilege_Escalation: 8 found
From: root→root | IP: N/A | Command: unknown | Time: 2025-05-08 10:14:30
From: root→root | IP: 192.168.1.101 | Command: unknown | Time: 2025-05-08 10:14:31
From: root→root | IP: 192.168.1.101 | Command: unknown | Time: 2025-05-08 10:14:32
From: root→root | IP: 192.168.1.101 | Command: unknown | Time: 2025-05-08 10:14:33
From: user→root | IP: N/A | Command: /bin/bash | Time: 2025-05-08 10:15:00
From: user→root | IP: N/A | Command: unknown | Time: 2025-05-08 10:15:02
From: jim→root | IP: 10.0.0.1 | Command: /usr/bin/top | Time: 2025-05-08 02:00:00
From: user→root | IP: 192.168.1.105 | Command: /bin/ls | Time: 2025-05-08 04:59:59

Recommendation: Monitor privilege escalation events for unauthorized access.
```

## Running Tests

* Include test files in the same directory as the files you are trying to test.

pytest test_log_analyzer.py

pytest test_log_parser.py

pytest test_report_generator.py

pytest test_API.py

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

Python 3.12.3

pytest (for testing)

## Team Members

Ishan Rajan

Evan Geisner

## Status

Core functionality complete

## Annotated Bibliography

- **AbuseIPDB API** (https://www.abuseipdb.com/)  
  Used to access current lists of suspicious IP addresses for threat detection and enrichment of log analysis results.

- **Regex101** (https://regex101.com/)  
  Utilized for testing and experimenting with regular expressions applied in `log_parser.py` to accurately extract IPs, timestamps, and login details from server logs.

- **Regexr** (https://regexr.com/)  
  Provided additional interactive regex debugging and examples, helping refine complex patterns needed for parsing diverse log formats.

- **Pytest Documentation** (https://docs.pytest.org/en/stable/)  
  Followed for writing and structuring unit tests to ensure the reliability of log parsing, analysis, and report generation components.




