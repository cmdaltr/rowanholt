"""Report branding: the derived palette, cleaning an uploaded logo, which brand a case's Word report
gets under each edition (the installation's under Pro, the case's under Services, Rowanholt's own on
Free) with stored choices kept across a licence change, and the brand API and full report through
the real backend (test_server_access.BackendCase). Licences are signed with a throwaway key.

Run: python3 -m unittest tests/unit/test_branding.py
"""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path
from unittest import mock

import test_server_access  # noqa: F401  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.report import theme as report_theme  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None
try:
    from PIL import Image
except ImportError:
    Image = None


def picture(fmt="PNG", size=(320, 120), colour=(31, 111, 235, 255), extra=b"") -> bytes:
    out = io.BytesIO()
    img = Image.new("RGBA", size, colour)
    if fmt == "JPEG":
        img = img.convert("RGB")
    img.save(out, format=fmt)
    return out.getvalue() + extra


class PaletteTest(unittest.TestCase):

    def test_a_light_primary_is_darkened_until_headings_read_and_says_so(self):
        palette, notes = report_theme.derive("#ffcc00", "#00aa88")
        heading = report_theme.parse_hex("#" + palette.heading)
        self.assertGreaterEqual(report_theme.contrast(heading, (255, 255, 255)), report_theme.TEXT_CONTRAST)
        self.assertGreaterEqual(report_theme.contrast(report_theme.parse_hex("#" + palette.subheading),
                                                      (255, 255, 255)), report_theme.TEXT_CONTRAST)
        self.assertEqual(len(notes), 2)
        self.assertIn("too light", notes[0])

    def test_a_dark_primary_is_used_as_given(self):
        palette, notes = report_theme.derive("#1f3a5f")
        self.assertEqual((palette.heading, palette.subheading, notes), ("1F3A5F", "1F3A5F", []))

    def test_rowanholts_own_style_is_the_colours_the_report_always_had(self):
        self.assertEqual(report_theme.ROWANHOLT.heading, "17365D")
        self.assertEqual(report_theme.ROWANHOLT.header_fill, "D5E3E8")


@unittest.skipIf(TestClient is None or Ed25519PrivateKey is None or Image is None, "backend requirements not installed")
class BrandingTest(BackendCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import branding
        import licence
        import webhooks
        cls.branding, cls.licence, cls.webhooks = branding, licence, webhooks
        cls.key = Ed25519PrivateKey.generate()
        public = cls.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        cls.keys = mock.patch.object(licence, "PUBLIC_KEYS", (public,))
        cls.keys.start()

    @classmethod
    def tearDownClass(cls):
        cls.keys.stop()
        super().tearDownClass()

    def setUp(self):
        folder = tempfile.mkdtemp()
        patch = mock.patch.dict(os.environ, {"ROWANHOLT_LICENCE": f"{folder}/licence.json",
                                             "ROWANHOLT_BRANDS": f"{folder}/brands.json",
                                             "ROWANHOLT_WEBHOOKS": f"{folder}/webhooks.json"})
        patch.start()
        self.addCleanup(patch.stop)
        self.folder = Path(folder)

    def licensed(self, edition):
        L = self.licence
        line = L.sign(self.key, L.rules().licence(L.new_id(), "Northwind Ltd", L.Edition(edition), 10,
                                                  date(2026, 11, 11), date(2099, 12, 31)))
        L.record_install(line, accepted_by="u1", accepted_by_name="Ada Admin <ada@example.org>")

    # ---- cleaning an upload ----

    def test_a_logo_is_redrawn_as_a_fresh_png_whatever_was_sent(self):
        cleaned = self.branding.clean_logo(picture(extra=b"<script>appended</script>"))
        self.assertTrue(cleaned.startswith(b"\x89PNG"))
        self.assertNotIn(b"appended", cleaned)
        self.assertEqual(Image.open(io.BytesIO(cleaned)).format, "PNG")
        jpeg = self.branding.clean_logo(picture("JPEG"))
        self.assertTrue(jpeg.startswith(b"\x89PNG"))
        big = Image.open(io.BytesIO(self.branding.clean_logo(picture(size=(3000, 600)))))
        self.assertLessEqual(max(big.size), self.branding.LOGO_MAX)

    def test_svg_gif_oversized_and_huge_uploads_are_refused(self):
        clean = self.branding.clean_logo
        problem = self.branding.BrandProblem
        with self.assertRaisesRegex(problem, "PNG or JPEG"):
            clean(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        with self.assertRaisesRegex(problem, "PNG or JPEG"):
            clean(picture("GIF"))
        with self.assertRaisesRegex(problem, "over 2 MB"):
            clean(b"\x89PNG" + b"\0" * (self.branding.UPLOAD_LIMIT + 1))
        with self.assertRaisesRegex(problem, "too large"):
            clean(picture(size=(5000, 4000), colour=(0, 0, 0, 0)))

    # ---- which brand a report gets ----

    def test_free_pro_and_services_choose_the_brand_and_choices_survive_a_licence_change(self):
        b = self.branding
        house = b.create("House", "#1f3a5f")
        client = b.create("Client Co", "#8b1e3f", prepared_for="Client Co")
        b.choose_installation(house["id"])
        b.choose_for_case("CASE-1", client["id"])
        self.assertIsNone(b.brand_for("CASE-1"))  # Free: Rowanholt's own, whatever is saved
        self.licensed("pro")
        self.assertEqual(b.brand_for("CASE-1")["id"], house["id"])  # Pro: the installation's brand
        self.licensed("services")
        self.assertEqual(b.brand_for("CASE-1")["id"], client["id"])  # Services: the case's own
        self.assertEqual(b.brand_for("CASE-2")["id"], house["id"])  # a case naming none: the installation's
        self.licence.remove()
        self.assertIsNone(b.brand_for("CASE-1"))
        stored = b.load()
        self.assertEqual((stored["installation"], stored["cases"]), (house["id"], {"CASE-1": client["id"]}))
        b.delete(client["id"])
        self.licensed("services")
        self.assertEqual(b.brand_for("CASE-1")["id"], house["id"])  # its brand gone: falls back

    # ---- through the backend ----

    def case(self, name):
        job_id = self.create_job(self.admin, name)
        host = self.evidence / "out" / name / "HOST1" / "artefacts" / "cooked"
        host.mkdir(parents=True, exist_ok=True)
        return job_id

    def report(self, job_id):
        resp = self.client.get(f"/api/jobs/{job_id}/case/full-report", headers=self.admin)
        self.assertEqual(resp.status_code, 200, resp.text)
        return zipfile.ZipFile(io.BytesIO(resp.content))

    def test_the_word_report_uses_the_installation_brand_on_pro_and_the_cases_on_services(self):
        made = self.client.post("/api/brands", headers=self.admin, json={"name": "House", "primary": "#1f3a5f"})
        self.assertEqual(made.status_code, 200, made.text)
        house = made.json()["id"]
        logo = self.client.put(f"/api/brands/{house}/logos/cover", headers=self.admin,
                               files={"file": ("logo.png", picture(), "image/png")})
        self.assertEqual(logo.status_code, 200, logo.text)
        self.assertTrue(logo.json()["logos"]["cover"])
        svg = self.client.put(f"/api/brands/{house}/logos/header", headers=self.admin,
                              files={"file": ("logo.svg", b"<svg/>", "image/svg+xml")})
        self.assertEqual(svg.status_code, 422)
        client = self.client.post("/api/brands", headers=self.admin, json={
            "name": "Client Co", "primary": "#8b1e3f", "prepared_for": "Client Co"}).json()["id"]
        self.assertEqual(self.client.put("/api/brands/installation", headers=self.admin,
                                         json={"brand_id": house}).status_code, 200)
        job_id = self.case("BRAND-CASE")
        self.assertEqual(self.client.put(f"/api/jobs/{job_id}/case/brand", headers=self.admin,
                                         json={"brand_id": client}).status_code, 200)

        free = self.report(job_id)
        self.assertIn("17365D", free.read("word/styles.xml").decode())
        self.assertFalse([n for n in free.namelist() if n.startswith("word/media/")])

        self.licensed("pro")
        pro = self.report(job_id)
        self.assertIn("1F3A5F", pro.read("word/styles.xml").decode())
        self.assertIn("word/media/cover.png", pro.namelist())
        self.assertNotIn("Prepared for Client Co", pro.read("word/document.xml").decode())

        self.licensed("services")
        services = self.report(job_id)
        self.assertIn("8B1E3F", services.read("word/styles.xml").decode())
        self.assertIn("Prepared for Client Co", services.read("word/document.xml").decode())

        markdown = self.client.get(f"/api/jobs/{job_id}/case/full-report", headers=self.admin,
                                   params={"format": "markdown"})
        self.assertEqual(markdown.status_code, 200)

    def test_brand_changes_are_admins_only_and_audited(self):
        self.assertEqual(self.client.get("/api/brands", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.post("/api/brands", headers=self.alice,
                                          json={"name": "X", "primary": "#000000"}).status_code, 403)
        made = self.client.post("/api/brands", headers=self.admin, json={"name": "Audited", "primary": "#123456"})
        from storage import AuditLogModel
        session = self.main.job_storage.Session()
        try:
            rows = [(r.action, r.resource_type, r.resource_id) for r in session.query(AuditLogModel)
                    .filter(AuditLogModel.resource_id == made.json()["id"])]
        finally:
            session.close()
        self.assertEqual(rows, [("brand_created", "brand", made.json()["id"])])
        listed = self.client.get("/api/brands", headers=self.admin).json()
        self.assertFalse(listed["report_branding"])
        self.assertIn("Rowanholt's own style", listed["says"])

    def test_a_built_report_sends_report_ready(self):
        self.licensed("pro")
        self.webhooks.add("https://soar.example.org/h", ["report.ready"], "k")
        sent = []
        for patch in (mock.patch.object(self.webhooks, "BACKGROUND", False),
                      mock.patch.object(self.webhooks, "_post", lambda url, body, headers: sent.append(body) or 200)):
            patch.start()
            self.addCleanup(patch.stop)
        job_id = self.case("REPORT-READY")
        self.report(job_id)
        [body] = sent
        message = json.loads(body)
        self.assertEqual(message["event"], "report.ready")
        self.assertEqual((message["data"]["case_number"], message["data"]["format"]), ("REPORT-READY", "docx"))


if __name__ == "__main__":
    unittest.main()
