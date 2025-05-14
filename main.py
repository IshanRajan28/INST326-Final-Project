import sys
import argparse
from log_analyzer import LogAnalyzer
import os
from report_generator import save_report, display_report

def parse_arguments():
    """
    Parse command line arguments for the program.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    
    Test cases:
        - Test with valid command line arguments
        - Test with missing required arguments
        - Test with invalid argument values
        - Test with help flag
    """
    parser = argparse.ArgumentParser(description="Security Log Analyzer " 
                                    "- Detect potential security threats in log file")
    parser.add_argument("log_file", type=str, help="Path to the log file to "
                        "analyze")
    parser.add_argument("-o", "--output", type=str, help="Path to save the output "
                        "report(if not specified, prints to console)")
    parser.add_argument("-t","--threshold", type=int, default=3, help="Threshold for "
                        "failed login attempts (default: 3)")
    parser.add_argument("-i","--suspicious-ips",type=str, help="Comma-separated list "
                        "of suspicious IP addresses to check for")
    parser.add_argument("-s","--start-time",type=int,default=23,help="Start hour for "
                        "unusual access time detection (24-hour format, default: 23)")
    parser.add_argument("-e", "--end-time", type=int,default=5,help="End hour for "
                        "unusual access time detection (24-hour format, default: 5)")
    
    return parser.parse_args()

def main():
    """
    Main function that drives the program flow.
    
    Handles initialization of the LogAnalyzer, execution of the analysis
    process, and presentation of results.
    """
    try:
        args = parse_arguments()
        
        if not os.path.isfile(args.log_file):
            print(f"Error: Log file '{args.log_file}' not found")
            sys.exit(1)
        
        suspicious_ip_list = []
        if args.suspicious_ips:
            ip_addresses = args.suspicious_ips.split(',')
            for ip in ip_addresses:
                clean_ip = ip.strip()
                suspicious_ip_list.append(clean_ip)
        
        else:
            suspicious_ip_list = None
        
        analyzer = LogAnalyzer(
            args.log_file,
            threshold=args.threshold,
            suspicious_ip_list=suspicious_ip_list,
            start_time=args.start_time,
            end_time=args.end_time
        )
        
        analyzer.parse_log_file()
        report = analyzer.generate_report()
        display_report(report)

        
        if args.output:
            if save_report(report,args.output):
                print(f"This report is also saved to {args.output}")
            
            else:
                print(f"Error: Could not save report to {args.output}")
                sys.exit(1)
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
            
    # Planned Tests:
    # Test complete execution flow with valid inputs
    # Test handling of file not found errors
    # Test handling of parsing errors
    # Test with various command line argument combinations

if __name__ == "__main__":
    """Entry point when run as a script."""
    main()