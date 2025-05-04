import sys
import argparse
from log_analyzer import LogAnalyzer

def parse_arguments():
    """
    Parse command line arguments for the program.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", type=str)
    parser.add_argument("-o", "--output", type=str)
    return parser.parse_args()

    # Planned Tests:
    # Test with valid command line arguments
    # Test with missing required arguments
    # Test with invalid argument values
    # Test with help flag

def main():
    """
    Main function that drives the program flow.
    
    Handles initialization of the LogAnalyzer, execution of the analysis
    process, and presentation of results.
    """
    
    args = parse_arguments()
    analyzer = LogAnalyzer(args.log_file)
    threats_summary = analyzer.run_analysis()
    report = analyzer.generate_report(threats_summary)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

    # Planned Tests:
    # Test complete execution flow with valid inputs
    # Test handling of file not found errors
    # Test handling of parsing errors
    # Test with various command line argument combinaitons