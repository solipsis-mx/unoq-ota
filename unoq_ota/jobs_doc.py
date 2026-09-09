from __future__ import annotations


class JobDocumentError(ValueError):
    pass


def parse_job_operation(document: dict | None) -> str:
    if not document:
        return "check"
    if not isinstance(document, dict):
        raise JobDocumentError("job document must be a JSON object")
    op = document.get("operation", "check")
    if op != "check":
        raise JobDocumentError(f"unsupported operation {op!r}")
    return "check"
