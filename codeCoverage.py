"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""
import warnings
warnings.filterwarnings("ignore")
import subprocess
import os
import pandas
from pathlib import PurePath
from lxml import etree


from FPRParser.FPRParser import FPRParser

# path to the ck jar file
# visit to download ck: https://github.com/mauricioaniche/ck
CKJAR = PurePath(r'/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/ck/target/ck-0.6.5-SNAPSHOT-jar-with-dependencies.jar')
CCoverage = PurePath(r'/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/data/codecoverage')
ALLFPRS = PurePath(
    r'/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/data/fprs'
)
PYFORTIFY = PurePath(r'/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/python-fortify/fprstats.py')

def getTotalLOC():
    totalLOC = 0
    for project in os.listdir(CCoverage):
        for file in os.listdir(project):
            if file == "class.csv":
                try:
                    df = pandas.read_csv(os.path.join(CCoverage, project, file))
                    totalLOC += df['loc'].sum()
                except pandas.errors.EmptyDataError:
                    print('Skipping empty dataframes: {:s}'.format(project))
    print(totalLOC)

def getTotalIssues(fpr):
    try:
        stat = subprocess.run(["python2", "-W", "ignore", PYFORTIFY, "-f", fpr, "-c"], capture_output=True)
        return stat
    except KeyError as kerr:
        print("{:s} does not have audit.xml: {:s}".format(fpr, kerr))

def executeCK(project):
    # Run CK code coverage on each project directory
    sck = subprocess.run(["java", "-jar", CKJAR, project], capture_output=True)
    return sck

if __name__ == "__main__":
    # import pdb
    # path to the downloaded java files
    vPath = PurePath(
        r'/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/data/validProjects'
    )
    vp = os.listdir(vPath)
    # getTotalLOC()
    totalFindings = 0
    for fpr in os.listdir(ALLFPRS):
        if not fpr == ".DS_Store":
            try:
                res = getTotalIssues(os.path.join(ALLFPRS, fpr))
            except KeyError as kerr:
                print("{:s} does not have audit.xml: {:s}".format(fpr, kerr))
            if res.stderr == "":
                for line in (res.stdout, b''):
                    line = line.rstrip().decode('utf8')
                    print(line)
            else:
                for line in (res.stderr, b''):
                    line = line.rstrip().decode('utf8')
                    if "Got" in line:
                        totalIssues = int(line.split()[29].strip("]").strip("["))
                        totalFindings += totalIssues
    print(totalFindings)
    # for project in vp:
    #     if not project == ".DS_Store":
    #         try:
    #             if not os.path.isdir(project):
    #                 os.mkdir(project)
    #             os.chdir(project)
    #             print("Changing directory to {:s}".format(project))
    #             res = executeCK(os.path.join(vPath, project))
    #             print("Code coverage: {:s}".format(project))
    #             os.chdir(
    #                 "/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/autoaudit/data/codecoverage"
    #             )
    #             # pdb.set_trace()
    #             # print(res.stderr)
    #             for line in (res.stdout, b''):
    #                 line = line.rstrip().decode('utf8')
    #                 print(line)
    #         except Exception as err:
    #             print("Exception occured: {:s}".format(err))
