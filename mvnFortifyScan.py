"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""

# Imports
import glob
import subprocess
import shutil
import os
from tqdm import tqdm

####################
# INTERNAL IMPORTS #
####################
from Crawler import Crawl

vp = Crawl.getValidProjects()
failed_scans = []
successful_scans = []
total_projects = len(vp)
print("Scanning {:d} project...go watch a movie!\n".format(len(vp)))
for idx, project in tqdm(enumerate(vp), desc="Scan Progress"):
    print("\n\nScanning {:d} of {:d} \n".format(idx + 1, total_projects))
    print("{:d} - Scanning {:s} located at {:s} \t\t(File Path length: {:d})\n".format(
        idx + 1,
        str(os.path.split(project)[0]).split("/")[-1],
        os.path.split(project)[0],
        len(os.path.split(project)[0]))
        )
    try:
        scanner_process = subprocess.run(
            [
                "sh",
                r"/Users/phitarth/Desktop/SANS_Masters/Research_Paper_1/fortifymaven/mvn-run.sh",
                os.path.split(project)[0],
                str(os.path.split(project)[0]).split("/")[-1]
            ],
            capture_output=True
        )
        for line in (scanner_process.stdout, b''):
            line = line.rstrip().decode('utf8')
            if "Failed" in line:
                failed_scans.append(str(os.path.split(project)[0]).split("/")[-1])
                print("Project added to failed scans list.")
            else:
                successful_scans.append(str(os.path.split(project)[0]).split("/")[-1])
                if not os.path.exists(os.path.abspath("data/fprs")):
                    os.makedirs(os.path.abspath("data/fprs"))
                try:
                    shutil.copy(glob.glob(os.path.split(project)[0]+"/target/fortify/*.fpr")[0], str(os.path.abspath("data/fprs/")))
                except IndexError as err:
                    print("Skipping FPR copy...")
            print(line)
    except Exception as err:
        print("Exception occured: {:s}".format(err))

with open(os.path.abspath("data/failed_scans.txt"), mode="a") as fs:
    for project in failed_scans:
        fs.write(project+"\n")

with open(os.path.abspath("data/success_scans.txt"), mode="a") as fs:
    for project in successful_scans:
        fs.write(project + "\n")
