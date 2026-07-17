from hashlib import sha256


def hash_string(value: str):
    return sha256(value.encode()).hexdigest()
