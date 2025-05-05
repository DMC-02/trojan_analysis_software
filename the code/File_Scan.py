import hashlib

def MD5_Collect(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()