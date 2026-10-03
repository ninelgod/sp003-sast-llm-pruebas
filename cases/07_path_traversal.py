import os

BASE = "/srv/files"

def read_doc(filename):
    with open(os.path.join(BASE, filename)) as f:
        return f.read()
