# Built in python imports
import sys
import logging
import zipfile
import shutil
import os

# Installed imports

# lxml imports
from lxml import etree


# LOGGER
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

logHandler = logging.StreamHandler(sys.stdout)
logHandler.setLevel(logging.INFO)

formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
logHandler.setFormatter(formatter)
log.addHandler(logHandler)

# Needed namespaces
# tree.getroot().nsmap can also be used to retreive these values
NS_MAP = {
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "ns2": "xmlns://www.fortify.com/schema/audit",
    "ns3": "xmlns://www.fortifysoftware.com/schema/activitytemplate",
    "ns4": "xmlns://www.fortifysoftware.com/schema/wsTypes",
    "ns5": "xmlns://www.fortify.com/schema/issuemanagement",
    "ns6": "http://www.fortify.com/schema/fws",
    "ns7": "xmlns://www.fortifysoftware.com/schema/runtime",
    "ns8": "xmlns://www.fortifysoftware.com/schema/seed",
    "ns9": "xmlns://www.fortify.com/schema/attachments",
}

CODEDIR = os.path.abspath("data/extracted")
LABELDIR = os.path.abspath("data/label")
if not os.path.exists(CODEDIR):
    os.makedirs(CODEDIR)

if not os.path.exists(LABELDIR):
    os.makedirs(LABELDIR)

class FPRParser():

    def __init__(self) -> None:
        self.findings = []
        self.FPR = self.FPR()

    class FPR(object):

        def __init__(self) -> None:
            self.nsmap = None
            self.project = None
            self.codePath = None

        def openFPR(self, infile):
            """
            TODO: Open FPR and make elementTrees/objectify
            """
            fprArchive = zipfile.ZipFile(infile, mode="r", compression=zipfile.ZIP_DEFLATED)
            self.project = os.path.basename(infile)[0:-4]
            fprArchive.extractall(os.path.abspath(os.path.join("FPRs", self.project)))
            auditFile = fprArchive.open("audit.xml")
            fvdlFile = fprArchive.open("audit.fvdl")
            codeIndex = fprArchive.open("src-archive/index.xml")

            # Making xml files into lxml objects/elementTrees
            self.auditTree = etree.parse(auditFile)
            self.nsmap = self.auditTree.getroot().nsmap
            # auditRoot = auditTree.getroot()
            auditFile.close()

            self.vulnTree = etree.parse(fvdlFile)
            # vulnRoot = vulnTree.getroot()
            fvdlFile.close()

            self.codeIndexTree = etree.parse(codeIndex)
            # codeIndexRoot = codeIndexTree.getroot()
            codeIndex.close()

            return self.auditTree, self.vulnTree, self.codeIndexTree

    class Finding():

        def __init__(self, instanceId, filepath, analysis, severity):
            self.instanceId = instanceId
            self.filepath = filepath
            self.analysis = analysis
            self.severity = severity

        def __str__(self):
            return "InstanceId:\t %s\nAnalysis:\t %s\nFilepath:\t %s\nSeverity:\t %s" % (self.instanceId, self.analysis, self.filepath, self.severity)

        def calculate_likelihood(self, accuracy, confidence, probability):
            """
            This method comes from Fortify Support Documentation
            Likelihood = (accuracy * confidence * probability) / 25
            """
            likelihood = (accuracy * confidence * probability) / 25
            self.likelihood = round(likelihood, 1)
            return round(likelihood, 1)

        def _priority(self, impact, likelihood):
            """
            This calculates Fortify Priority Order
            """
            if impact >= 2.5 and likelihood >= 2.5:
                self.priority = '1 - Resolve Immediately'
                self.criticality = "Critical"
            elif impact >= 2.5 > likelihood:
                self.priority = '2 - Give High Attention'
                self.criticality = "High"
            elif impact < 2.5 <= likelihood:
                self.priority = '3 - Normal'
                self.criticality = "Medium"
            elif impact < 2.5 and likelihood < 2.5:
                self.priority = '4 - Low'
                self.criticality = "Low"

    def getAllSusIssues(self, infile):
        """
        Returns: All suspicious findings
        """
        audit = self.FPR.openFPR(infile)[0]

        # get all issues from audit.xml
        issues = audit.getroot().iterdescendants("{*}Issue")

        sus_issues = []
        issue_count = 0

        # iterate over all sus issues
        for issue in issues:
            analysis = issue.xpath(".//ns2:Value[contains(text(), 'Suspicious')]", namespaces=self.FPR.nsmap)
            if (not len(analysis) == 0) and (analysis[0].text == "Suspicious"):
                sus_issues.append(issue)
                issue_count += 1

        return sus_issues, issue_count

    def getAllFPIssues(self, infile):
        """
        Returns: All 'Not an Issue findings
        """
        audit = self.FPR.openFPR(infile)[0]

        # get all issues from audit.xml
        issues = audit.getroot().iterdescendants("{*}Issue")

        fp_issues = []
        issue_count = 0

        # iterate over all sus issues
        for issue in issues:
            analysis = issue.xpath(".//ns2:Value[contains(text(),'Not an Issue')]", namespaces=self.FPR.nsmap)
            if (not len(analysis) == 0) and (analysis[0].text =="Not an Issue"):
                fp_issues.append(issue)
                issue_count += 1

        return fp_issues, issue_count

    def getAllAnalyzedIssues(self, infile):
        """
        
        """

        fp_issues = self.getAllFPIssues(infile)[0]
        fp_count = self.getAllFPIssues(infile)[1]

        sus_issues = self.getAllSusIssues(infile)[0]
        sus_count = self.getAllSusIssues(infile)[1]

        # log.info("False Positive Count: %d" % fp_count)
        # log.info("Suspicious Count: %d" % sus_count)
        all_issues = [*sus_issues, *fp_issues]
        # log.info("All Issues: %d" % (len(all_issues)))
        return all_issues

    def buildFindings(self, infile):
        """
        TODO: Remove all filepath that do not end with .java findings.
        """
        # get all vulnerabilities
        fvdl = self.FPR.openFPR(infile)[1]
        vulns = fvdl.getroot().iterdescendants("{*}Vulnerability")
        all_issues = self.getAllAnalyzedIssues(infile)

        for vul in vulns:
            vinstanceId = vul.find(".//{*}InstanceID").text
            for issue in all_issues:
                instanceid = issue.attrib["instanceId"]
                if vinstanceId == instanceid:
                    analysis = issue.xpath(".//ns2:Value/text()", namespaces=self.FPR.nsmap)[1]
                    severity = vul.find(".//{*}InstanceSeverity").text
                    tmpfilepath = vul.find(".//{*}SourceLocation").attrib['path']
                    if tmpfilepath.endswith(".java"):
                        filepath = tmpfilepath
                        # confidence = float(vul.find(".//{*}Confidence").text)
                        finding = self.Finding(instanceid, filepath, analysis, severity)
                        self.findings.append(finding)
        log.info("Finished building findings from FPR.")

    def mapFilenameToCode(self, infile):
        """
        Function maps filename to code snippet for extraction
        Function also creates a label file corresponding to code snippet and saved as analysis
        """
        codeIndex = self.FPR.openFPR(infile)[2]
        index = codeIndex.getroot().iterdescendants("{*}entry")

        exFPRPath = os.path.abspath("FPRs")
        fullPath = os.path.join(exFPRPath, self.FPR.project)
        codeLocation = os.path.join(fullPath, "src-archive")

        for i in index:
            indexFilePath = i.attrib["key"]
            for finding in self.findings:
                filepath = finding.filepath
                if indexFilePath == filepath:
                    srcLocation = i.xpath(".//text()")[0][12:]
                    shutil.copy(os.path.join(codeLocation, srcLocation), CODEDIR)
                    with open(LABELDIR + "/labels.csv", "a") as label:
                        label.write(os.path.join(CODEDIR, ''.join([str(srcLocation), self.FPR.project , '.java'])) + "," + finding.analysis + "\n")
                    log.info("Copied extracted code to /data/extracted")

        for root, dir, f in os.walk(CODEDIR):
            for i in f:
                if not i.lower().endswith(".java"):
                    os.rename(os.path.join(CODEDIR, i), os.path.join(CODEDIR, ''.join([str(i), self.FPR.project , '.java'])))
