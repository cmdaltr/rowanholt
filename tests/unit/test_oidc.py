"""Unit tests for single sign-on (auth/oidc.py) against a fake identity provider.

A real RSA key signs the ID tokens; discovery, the key set and the token endpoint are
stand-ins. Needs the backend's Python requirements; skipped without them.

Run: python3 -m unittest tests/unit/test_oidc.py
"""

import asyncio
import base64
import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TMP = tempfile.mkdtemp(prefix="rivendell-oidc-")
os.chdir(TMP)  # the backend's settings read .env from here, never the repository's
os.environ.update({
    "USERS_FILE": f"{TMP}/users.json",
    "SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
    "RIVENDELL_PUBLIC_URL": "https://rivendell.test",
    "OIDC_ISSUER": "https://idp.test",
    "OIDC_CLIENT_ID": "rivendell",
    "OIDC_CLIENT_SECRET": "s3cret",
    "OIDC_ADMIN_GROUP": "dfir-leads",
    "OIDC_ALLOWED_GROUP": "dfir",
})

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk, jwt
except ImportError:
    rsa = None

BACKEND = Path(__file__).resolve().parents[2] / "src" / "web" / "backend"
sys.path.insert(0, str(BACKEND))
ISSUER = "https://idp.test"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@unittest.skipIf(rsa is None, "backend requirements (python-jose, cryptography) not installed")
class OidcTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Another test file may have imported config first, before this file's OIDC environment
        # was set: start the backend's modules afresh.
        for name in [n for n in sys.modules if n == "config" or n == "auth" or n.startswith("auth.")]:
            del sys.modules[name]
        sys.path.insert(0, str(BACKEND))  # ahead of src/analysis, which has a config package of its own
        from auth import oidc
        cls.oidc = oidc
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        public = jwk.construct(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(), "RS256").to_dict()
        public.update({"kid": "k1", "use": "sig", "alg": "RS256"})
        cls.documents = {
            f"{ISSUER}/.well-known/openid-configuration": {
                "issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"},
            f"{ISSUER}/jwks": {"keys": [{k: (v.decode() if isinstance(v, bytes) else v) for k, v in public.items()}]},
        }

    def setUp(self):
        Path(os.environ["USERS_FILE"]).unlink(missing_ok=True)

    def id_token(self, nonce, access_token="at", **claims):
        at_hash = b64url(hashlib.sha256(access_token.encode()).digest()[:16])
        body = {"iss": ISSUER, "aud": "rivendell", "sub": "u-123", "nonce": nonce, "at_hash": at_hash,
                "iat": int(time.time()), "exp": int(time.time()) + 300,
                "preferred_username": "aragorn@gondor.example", "email": "aragorn@gondor.example",
                "name": "Aragorn", "groups": ["dfir"], **claims}
        return jwt.encode(body, self.pem, algorithm="RS256", headers={"kid": "k1"})

    def claims(self, flow, token):
        async def get_json(url):
            return self.documents[url]

        response = mock.Mock(status_code=200)
        response.json.return_value = {"id_token": token, "access_token": "at"}
        client = mock.AsyncMock()
        client.__aenter__.return_value.post.return_value = response
        with mock.patch.object(self.oidc, "_get_json", get_json), \
                mock.patch.object(self.oidc.httpx, "AsyncClient", return_value=client):
            return asyncio.run(self.oidc.claims_for("code", flow))

    def test_valid_token_creates_user(self):
        flow = self.oidc.new_flow()
        user = self.oidc.user_for(self.claims(flow, self.id_token(flow["nonce"])))
        self.assertEqual(user["username"], "aragorn@gondor.example")
        self.assertEqual(user["role"], "user")
        self.assertFalse(user["hashed_password"])
        again = self.oidc.user_for(self.claims(flow, self.id_token(flow["nonce"])))
        self.assertEqual(again["id"], user["id"])  # matched on issuer and subject

    def test_admin_group_makes_admin(self):
        flow = self.oidc.new_flow()
        user = self.oidc.user_for(self.claims(flow, self.id_token(flow["nonce"], groups=["dfir", "dfir-leads"])))
        self.assertEqual(user["role"], "admin")

    def test_outside_allowed_group_refused(self):
        flow = self.oidc.new_flow()
        claims = self.claims(flow, self.id_token(flow["nonce"], groups=["finance"]))
        with self.assertRaises(self.oidc.SignInRefused):
            self.oidc.user_for(claims)

    def test_wrong_nonce_refused(self):
        flow = self.oidc.new_flow()
        with self.assertRaises(self.oidc.SignInRefused):
            self.claims(flow, self.id_token("someone-elses-nonce"))

    def test_wrong_audience_refused(self):
        flow = self.oidc.new_flow()
        with self.assertRaises(self.oidc.SignInRefused):
            self.claims(flow, self.id_token(flow["nonce"], aud="another-app"))

    def test_state_cookie_round_trip_and_tamper(self):
        flow = self.oidc.new_flow()
        sealed = self.oidc.seal(flow)
        self.assertEqual(self.oidc.unseal(sealed)["state"], flow["state"])
        self.assertIsNone(self.oidc.unseal(sealed[:-2] + "xx"))

    def test_pkce_challenge(self):
        # RFC 7636 appendix B
        self.assertEqual(self.oidc.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                         "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")


if __name__ == "__main__":
    unittest.main()
