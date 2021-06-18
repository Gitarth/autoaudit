# Imports
import sys

def pathify(file_path):
    pathCount = 0
    paths = []
    with open(file_path, "r", encoding="utf-8") as file:
        with open(file_path + "paths.txt", "w") as pFile:
            for line in file:
                listOfPaths = line.split()
                pathCount += 1
                thePaths = enumerate(listOfPaths)
                for idx, path in thePaths:
                    if path.count(",") == 0:
                        temp = path
                    elif idx == 1:
                        path = temp + " " + path
                        paths.append(path)
                        pFile.write(path+"\n")
                    else:
                        pFile.write(path+"\n")
                        paths.append(paths)
    

if __name__ == "__main__":
    infile = sys.argv[1]
    pathify(infile)