"""The docs describe only the sign-in that's built: password, single sign-on and API tokens.

Rowanholt has no MFA. The MFA routes are in src/web/backend/auth/routes.py, which the backend
doesn't mount, and the docs, the README and the web app's guide used to describe setting it up.

Run: python3 -m pytest tests/unit/test_docs_mfa.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md", ROOT / "INSTALL.md"]
WEB_COPY = [ROOT / "src/web/frontend/src/components/HelpPage.js", ROOT / "src/web/frontend/src/guide/content.js"]

# Each describes MFA as something a person can turn on or use
CLAIMS = (
    "Enable MFA",
    "Login with MFA",
    "/api/auth/mfa/",
    "MFA provides",
    "Save backup codes",
    "MFA setup",
    "MFA disable",
    "Added MFA",
    "TOTP secrets are encrypted",
    "password, multi-factor authentication",
)


def test_no_doc_or_web_copy_claims_mfa_is_built():
    found = [f"{path.relative_to(ROOT)}: {claim}" for path in DOCS + WEB_COPY if path.exists()
             for claim in CLAIMS if claim in path.read_text(encoding="utf-8")]
    assert found == []


def test_the_security_and_usage_guides_say_there_is_none_and_where_to_get_it():
    for name in ("SECURITY.md", "USAGE.md"):
        text = (ROOT / "docs" / name).read_text(encoding="utf-8")
        assert "no built-in MFA" in text, name
        assert "identity provider" in text and "ROWANHOLT_LOCAL_LOGIN=false" in text, name
