import os

UPLOAD_DIR = "/srv/uploads"


def read_upload(filename: str) -> str:
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, encoding="utf-8") as f:
        return f.read()
