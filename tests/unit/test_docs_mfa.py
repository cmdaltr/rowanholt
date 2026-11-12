"""The docs describe the MFA that's built: TOTP for a team server's password accounts, backup codes,
an admin's reset, the ROWANHOLT_REQUIRE_MFA policy, and single sign-on accounts' MFA at the
identity provider.

Until 12 November 2026 Rowanholt had no MFA, and the docs said so (commit 4a8e8fa); before that they
described routes in auth/routes.py that the backend never mounted. This keeps both of the old
claims out: that there's no MFA, and the unmounted design's endpoints.

Run: python3 -m pytest tests/unit/test_docs_mfa.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md", ROOT / "INSTALL.md"]
WEB_COPY = [ROOT / "src/web/frontend/src/components/HelpPage.js", ROOT / "src/web/frontend/src/guide/content.js"]

# Each says Rowanholt has no MFA of its own, which is no longer true
NONE_CLAIMS = (
    "no built-in MFA",
    "has no MFA",
    "no MFA of its own",
    "Rowanholt has none of its own",
    "There is no MFA",
    "no MFA step",
    "no built-in multi-factor",
    "MFA panel doesn't work",
)
# The unmounted design's endpoints (auth/routes.py), which the built-in MFA doesn't have
OLD_ENDPOINTS = ("/api/auth/mfa/verify", "/auth/mfa/verify")


def _texts():
    return {path: path.read_text(encoding="utf-8") for path in DOCS + WEB_COPY if path.exists()}


def test_no_doc_or_web_copy_says_there_is_no_mfa():
    found = [f"{path.relative_to(ROOT)}: {claim}" for path, text in _texts().items()
             for claim in NONE_CLAIMS + OLD_ENDPOINTS if claim in text]
    assert found == []


def test_the_security_usage_and_server_guides_describe_what_is_built():
    for name in ("SECURITY.md", "USAGE.md", "SERVER.md"):
        text = (ROOT / "docs" / name).read_text(encoding="utf-8")
        for fact in ("backup code", "mfa-reset", "ROWANHOLT_REQUIRE_MFA", "identity provider"):
            assert fact in text, f"{name}: {fact}"
    security = (ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    for fact in ("RFC 6238", "HKDF", "Fernet", "HMAC-SHA256", "API tokens", "audit_logs"):
        assert fact in security, fact


def test_the_api_reference_documents_the_endpoints_and_the_changed_login():
    text = (ROOT / "docs" / "API.md").read_text(encoding="utf-8")
    for endpoint in ("POST /auth/login/mfa", "/auth/mfa/setup", "/auth/mfa/enable", "/auth/mfa/disable",
                     "/auth/mfa/backup-codes", "/api/auth/users/{user_id}/mfa"):
        assert endpoint in text, endpoint
    assert '"mfa_required": true' in text and '"challenge"' in text


def test_the_config_reference_and_the_in_app_guide_mention_it():
    assert "ROWANHOLT_REQUIRE_MFA" in (ROOT / "docs" / "CONFIG.md").read_text(encoding="utf-8")
    guide = (ROOT / "src/web/frontend/src/guide/content.js").read_text(encoding="utf-8")
    assert "multi-factor authentication" in guide and "backup codes" in guide and "identity provider" in guide
    for name in ("README.md", "ARCHITECTURE.md"):
        assert "TOTP" in (ROOT / "docs" / name).read_text(encoding="utf-8"), name
