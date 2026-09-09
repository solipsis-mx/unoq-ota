import pytest
from unoq_ota.jobs_doc import JobDocumentError, parse_job_operation


def test_missing_document_is_check():
    assert parse_job_operation(None) == "check"
    assert parse_job_operation({}) == "check"


def test_explicit_check():
    assert parse_job_operation({"operation": "check"}) == "check"


def test_rejects_unknown_operation():
    with pytest.raises(JobDocumentError):
        parse_job_operation({"operation": "apply"})


def test_ignores_url_fields():
    assert parse_job_operation({"operation": "check", "url": "https://evil.example/m.json"}) == "check"
