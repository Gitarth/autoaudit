"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""
# ---------- IMPORTS -----------
import os
import zipfile
import requests as re
import csv
import math
import shutil
import glob

# ---------- CONSTANTS -----------
TOKEN = "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"
USER = "gitarth"
OUTPUT_DIR = os.path.abspath("data")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

REPO_URL = "https://api.github.com/search/repositories?q="
RAW_SEARCH_URL = "https://api.github.com/search/code?q="

# ------ QUERIES ---------
# GETMVNPROJECTS = re.utils.quote("filename:pom.xml language:Java")
# GETMVNPROJECTS = "pom.xml+language%3AJava"
GETMVNPROJECTS = "pom.xml"
GETJAVAPROJECTS = "language%3AJava"

STAR_PARAM = "&s=stars"
PP_PARAM = "&per_page=100"
PARAMS = STAR_PARAM+PP_PARAM
HEADERS = {'Accept': 'application/vnd.github.v3+json'}


def getUrl(url):
    """ Returns a URL's body """
    res = re.get(url, auth=(USER, TOKEN), headers=HEADERS)
    return res.json()

def download(url, fileName, chunk_size=128):
    res = re.get(url, stream=True)
    outputPath = OUTPUT_DIR+"/applications/"+fileName+".zip"
    os.makedirs(os.path.dirname(outputPath), exist_ok=True)
    with open(outputPath, "wb") as gR:
        for chunk in res.iter_content(chunk_size=chunk_size):
            gR.write(chunk)

def moveBadZip(zip):
    badzip = OUTPUT_DIR + "/badzip/"
    os.makedirs(os.path.dirname(badzip), exist_ok=True)
    try:
        shutil.move(os.path.abspath("data/applications/"+zip), os.path.abspath(badzip+zip))
    except PermissionError:
        print("Permission error occured, but zip was moved succesfully.")

def extract(directory):
    out = OUTPUT_DIR + "/extractedApps/"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    for root, dir, zips in os.walk(directory):
        for zip in zips:
            if zip.endswith('.zip'):
                try:
                    archive = zipfile.ZipFile(os.path.abspath("data/applications/"+zip), mode="r")
                except zipfile.BadZipFile:
                    print("{:s} is not a zip file.".format(zip))
                    moveBadZip(zip)
                except FileNotFoundError:
                    print("Skipping zip file {:s}".format(zip))
                    moveBadZip(zip)
                
                if os.path.exists(os.path.abspath("data/extractedApps/"+zip[:-4])):
                        pass
                else:
                    try:
                        print("Extracting {:s} ...".format(zip))
                        archive.extractall(out+os.path.basename(zip)[0:-4])
                    except FileNotFoundError:
                        print("Skipping zip file {:s}".format(zip))
                        moveBadZip(zip)

def getValidProjects():
    # import pdb; pdb.set_trace()
    # Requires full path to validPorjects dir
    # thePath = "C:/Users/phitarth/Desktop/researchpaper/fake-pos-detect/Crawler/data/validProjects/" + "**/pom.xml"
    from pathlib import Path
    thePath = os.path.abspath("data/validProjects/**/pom.xml")
    poms = glob.glob(thePath, recursive=True)
    valid_project_path = []
    visited_projects = []
    for pom in poms:
        p = Path(pom)
        project = p.parts[9]
        if project not in visited_projects:
            # print("Project pom added: {:s}\nPom Location: {:s}".format(project, str(p)))
            visited_projects.append(project)
            valid_project_path.append(p)
    # print(len(visited_projects))
    return valid_project_path
    

def cleanUp(dir):
    from pathlib import Path
    out = OUTPUT_DIR + "/validProjects/"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    poms = glob.glob(dir+"**/pom.xml", recursive=True)
    valid_projects = []
    for pom in poms:
        pth = Path(os.path.split(pom)[0])
        repo_name = pth.parts[9]
        if repo_name not in valid_projects:
            valid_projects.append(repo_name)

    for project in valid_projects:
        shutil.move(os.path.abspath(OUTPUT_DIR + "/extractedApps/" + project), out + project)
    print("Moved all scannable projects to {:s}".format(out))
    

def execute():
    print("Querying url: %s" % REPO_URL + GETMVNPROJECTS + PARAMS)
    maven_projects_RES = getUrl(REPO_URL + GETMVNPROJECTS + PARAMS)
    count = maven_projects_RES['total_count']
    actualCount = 0
    print("Total Repositories Found: {:d}\n".format(count))
    numPages = int(math.ceil(count) / 100.0)
    print("Total number of pages: {:d}\n".format(numPages))
    csvFilename = OUTPUT_DIR+"/gitapps.csv"
    with open(csvFilename, "w+", newline='') as appCsv:
        repo_writer = csv.writer(appCsv, delimiter=",")
        if appCsv.tell() == 0:
            repo_writer.writerow(["Repository", "Full Name", "URL", "ZIP_URL"])
        for page in range(1, numPages + 1):
            print("Page {:d} of {:d}\n".format(page, numPages))
            data = getUrl(REPO_URL + GETMVNPROJECTS + PARAMS + "&page=" + str(page))
            for repo in data['items']:
                # Repository information
                repository = repo['name']
                clone_url = repo['clone_url']
                fileName = repo['full_name'].replace("/", "-")
                zip_url = clone_url[:len(clone_url) - 4] + "/archive/master.zip"
                size = repo['size']
                if size >= 100:
                    print("Downloading {:s}".format(repository))
                    download(zip_url, fileName)
                    # print("Repository Name: {:s}\nURL: {:s}\n".format(repository, clone_url))
                    os.makedirs(os.path.dirname(csvFilename), exist_ok=True)
                    repo_writer.writerow([repository, fileName, clone_url, zip_url])
                    actualCount += 1
    print("Downloaded a total of {:d} repositories. \n".format(actualCount))


if __name__ == "__main__":
    """
    Uncomment the method call as needed. You shouldn't need to change any paths.
    """

    # execute()
    # extract(OUTPUT_DIR+"/applications/")
    # cleanUp(OUTPUT_DIR+"/extractedApps/")
    getValidProjects()