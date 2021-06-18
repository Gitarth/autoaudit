"""
@author: Hitarth Patel
@Project: Auto-Auditor
"""

# Imports 
import subprocess


####################
# INTERNAL IMPORTS #
####################
from Crawler import Crawl

test = subprocess.run(["dir"], stdout=subprocess.PIPE, shell=True)
vp = Crawl.getValidProjects()
# print(vp)
print(test.stdout)