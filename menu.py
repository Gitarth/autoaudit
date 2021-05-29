"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""
# PYTHON IMPORTS
import argparse
from lxml import etree

# INTERNAL IMPORTS
from FPRParser.FPRParser import FPRParser

def main():
    """
    Initialize and start Auto-Auditor
    """
    # Initialize a parser
    parser = argparse.ArgumentParser(description="Auto-Audit: Here to automate your analysis")

    # Add arguments
    parser.add_argument("-f", "--fpr", required=True, help="Enter the FPR that needs to be parsed.")

    # let the parser parse args
    args = parser.parse_args()
    fparser = FPRParser()
    FPRParser().getAllAnalyzedIssues(args.fpr)
    fparser.buildFindings(args.fpr)
    fparser.mapFilenameToCode(args.fpr)
    
    # FPRParser().buildFindings(args.fpr)
    
if __name__ == "__main__":
    main()