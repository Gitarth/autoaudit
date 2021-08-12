"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""
# PYTHON IMPORTS
import os
import argparse
from lxml import etree

# INTERNAL IMPORTS
from FPRParser.FPRParser import FPRParser

DATA_DIR = "/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/data/"

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError()

def main():
    """
    Initialize and start Auto-Auditor
    """
    # Initialize a parser
    parser = argparse.ArgumentParser(description="Auto-Audit: Here to automate your analysis")

    fprgroups = parser.add_mutually_exclusive_group(required=True)
    # Add arguments
    fprgroups.add_argument("-d", "--directoryFPRs", type=dir_path, help="Enter a directory containing valid FPRs.")
    fprgroups.add_argument("-f", "--fpr", help="Enter the FPR that needs to be parsed.")
    parser.add_argument("-ld", "--label-data", help="Enter the file_path of data to correspond labels.")

    # let the parser parse args
    args = parser.parse_args()

    if args.directoryFPRs:
        for file in os.listdir(args.directoryFPRs):
            print()
            fparser = FPRParser()
            fparser.FPR.openFPR(
                os.path.join(DATA_DIR + "/analyzedFPRs/",file))
            fparser.buildFindings(
                os.path.join(DATA_DIR + "/analyzedFPRs/", file))
            fparser.mapFilenameToCode(
                os.path.join(DATA_DIR + "/analyzedFPRs/", file))
        
        
    elif args.fpr:
        fparser = FPRParser()
        fparser.FPR.openFPR(args.fpr)
        # FPRParser().getAllAnalyzedIssues(args.fpr)
        fparser.buildFindings(args.fpr)
        # print(getattr(fparser.findings[0], 'type'))
        fparser.mapFilenameToCode(args.fpr)

if __name__ == "__main__":
    main()