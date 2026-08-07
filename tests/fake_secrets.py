"""Helpers for building secret-shaped test values.

Tests that exercise redaction and scrubbing need strings that *look* like real
Vault tokens. Writing those as source literals trips the gitleaks pre-commit
hook, and silencing the scanner with an allowlist would blunt it for genuine
leaks — so the values are assembled at runtime from harmless fragments instead.

The results are meaningless, but they match the shapes the redaction logic must
catch, which is the only property these tests depend on.
"""


def fake_token(scheme: str, body: str) -> str:
    """Return a token-shaped string, e.g. fake_token("hvs", "abc") -> "hvs.abc".

    Args:
        scheme: Token scheme prefix without the dot ("hvs", "hvb", "hvr", "s").
        body: Arbitrary body text.
    """
    return f"{scheme}.{body}"
