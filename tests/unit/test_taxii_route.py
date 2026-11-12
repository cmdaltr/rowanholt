"""POST /api/threat-intel/taxii (src/web/backend/threat_intel_routes.py): a TAXII server that refuses
or can't be reached is a 502 with samarkand's message. TaxiiProblem has been an OSError since
samarkand 0.1.1, so the route's `except OSError` catches it with no wrapper of Rowanholt's. Nothing is
fetched: samarkand.taxii.fetch_objects is swapped out.

Run from tests/unit: python3 -m unittest test_taxii_route.py
"""

import unittest
from unittest import mock

from test_server_access import BackendCase, TestClient

COLLECTION = "https://taxii.example.test/api/collections/abc/"


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class TaxiiRouteTest(BackendCase):
    def pull(self):
        return self.client.post("/api/threat-intel/taxii", headers=self.admin, json={"url": COLLECTION})

    def test_a_refusal_is_a_502_with_the_reason(self):
        from samarkand import taxii
        refused = taxii.TaxiiProblem("The TAXII server refused the credentials (HTTP 401).")
        with mock.patch.object(taxii, "fetch_objects", side_effect=refused):
            resp = self.pull()
        self.assertEqual(resp.status_code, 502, resp.text)
        self.assertEqual(resp.json()["detail"],
                         "Couldn't read the TAXII collection: The TAXII server refused the credentials (HTTP 401).")

    def test_the_objects_become_indicators(self):
        from samarkand import taxii
        objects = [{"type": "indicator", "id": "indicator--1", "name": "C2",
                    "pattern": "[domain-name:value = 'c2.taxii.example.test']"},
                   {"type": "indicator", "pattern": "[domain-name:value = 'no-id.example.test']"}]
        with mock.patch.object(taxii, "fetch_objects", return_value=objects) as fetch:
            resp = self.pull()
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["read"], 1)  # the object without an id gives no row
        self.assertEqual(fetch.call_args.args, (COLLECTION,))
        self.assertEqual(fetch.call_args.kwargs["user_agent"], "Rowanholt (TAXII 2.1 client)")


if __name__ == "__main__":
    unittest.main()
