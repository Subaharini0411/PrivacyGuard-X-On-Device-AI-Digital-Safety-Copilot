"""Unit tests for PrivacyGuard X Validators & File Utils."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.validators import validate_text_input, validate_file_size, validate_url_syntax
from utils.file_utils import sanitize_filename, generate_audit_report_json


def test_text_validator():
    ok, err = validate_text_input("Some valid text content")
    assert ok is True

    ok, err = validate_text_input("")
    assert ok is False
    assert "empty" in err.lower()


def test_file_size_validator():
    ok, _ = validate_file_size(1024)
    assert ok is True

    ok, err = validate_file_size(0)
    assert ok is False

    ok, err = validate_file_size(30 * 1024 * 1024)
    assert ok is False
    assert "exceeds" in err.lower()


def test_url_syntax_validator():
    ok, _ = validate_url_syntax("https://example.com/api")
    assert ok is True

    ok, err = validate_url_syntax("")
    assert ok is False


def test_sanitize_filename():
    unsafe = "../../etc/passwd.png"
    safe = sanitize_filename(unsafe)
    assert ".." not in safe
    assert "/" not in safe
    assert safe.endswith("passwd.png")
