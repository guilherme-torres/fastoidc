import pytest

from fastoidc.utils.hashing import hash_string


def test_hash_string_returns_hex_string():
    result = hash_string("qualquer-valor")
    assert isinstance(result, str)
    assert len(result) == 64


def test_hash_string_is_deterministic():
    assert hash_string("abc") == hash_string("abc")


def test_hash_string_different_inputs_produce_different_hashes():
    assert hash_string("abc") != hash_string("xyz")


def test_hash_string_empty_string():
    result = hash_string("")
    assert isinstance(result, str)
    assert len(result) == 64
