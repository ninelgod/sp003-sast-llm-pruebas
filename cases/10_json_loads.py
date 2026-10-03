import json

def load_session(raw_bytes):
    return json.loads(raw_bytes.decode("utf-8"))
