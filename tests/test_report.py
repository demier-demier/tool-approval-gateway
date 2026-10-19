from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from approval_gateway.demo import run_demo
from approval_gateway.report import CSS, JS, render_report


class ReportTest(unittest.TestCase):
    def test_embedded_untrusted_content_cannot_close_script(self):
        attack = '</script><script>alert("fixture")</script><img src=x onerror=alert(1)>&\u2028'
        html = render_report({"scenarios": [], "text": attack})
        self.assertNotIn(attack, html)
        self.assertIn("\\u003c/script\\u003e", html)
        embedded = html.split('<script id="report-data" type="application/json">', 1)[1].split("</script>", 1)[0]
        self.assertEqual(json.loads(embedded)["text"], attack)
        self.assertNotIn("innerHTML", JS)

    def test_csp_hashes_match_exact_inline_assets(self):
        html = render_report({"scenarios": []})
        for source in (CSS, JS):
            value = base64.b64encode(hashlib.sha256(source.encode()).digest()).decode()
            self.assertIn("'sha256-" + value + "'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn("unsafe-inline", html)

    def test_complete_demo_persists_expected_evidence_and_preserves_previous_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = run_demo(directory)
            self.assertEqual(result["expected_outcomes_verified"], 15)
            self.assertEqual(result["external_actions"], 0)
            data = json.loads((directory / "report.json").read_text())
            self.assertTrue(all(case["actual"] == case["expected"] for case in data["scenarios"]))
            self.assertEqual(sum(case["actual"] == "simulated_success" for case in data["scenarios"]), 3)
            self.assertEqual(len(data["audit"]), 18)
            self.assertNotIn("approval_token", json.dumps(data))
            self.assertTrue((directory / "report.html").is_file())
            with self.assertRaises(FileExistsError):
                run_demo(directory)


if __name__ == "__main__":
    unittest.main()
