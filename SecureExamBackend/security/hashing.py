import hashlib


def generate_hash(data):

    return hashlib.sha256(data).hexdigest()