from hashlib import sha256


def hash_string(value: str):
    """Computes the SHA-256 hash of a string and returns its hexadecimal representation."""
    return sha256(value.encode()).hexdigest()
