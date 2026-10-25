"""Tests for registry parser helper functions."""
from afd.parsers import registry_parser


def test_rot13_decoding():
    assert registry_parser._rot13("PPyrnare.rkr") == "CCleaner.exe"
    assert registry_parser._rot13("fqryrgr.rkr") == "sdelete.exe"
    assert registry_parser._rot13("Plain text 123") == "Cynva grkg 123"
    assert registry_parser._rot13(registry_parser._rot13("Double ROT13")) == "Double ROT13"
