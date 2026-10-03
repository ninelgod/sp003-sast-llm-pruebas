import os

BASE = os.path.realpath("/srv/files")

def read_doc(filename):
    full = os.path.realpath(os.path.join(BASE, filename))
    if not full.startswith(BASE + os.sep):
        raise PermissionError("ruta fuera del directorio permitido")
    with open(full) as f:
        return f.read()
