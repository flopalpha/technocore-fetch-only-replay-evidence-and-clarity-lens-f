import hashlib
import json
import tempfile
import pathlib
import unittest
import lens


class TestGaps(unittest.TestCase):
    def test_gap_and_duplicate_and_reorder(self):
        records = [{"seq": 1}, {"seq": 2}, {"seq": 2}, {"seq": 5}, {"seq": 3}]
        rep = lens.analyze_sequence(records, wait_window=10)
        self.assertEqual(rep["min_seq"], 1)
        self.assertEqual(rep["max_seq"], 5)
        self.assertEqual(rep["gaps"], [[4, 4]])
        self.assertEqual(rep["duplicates"], {2: 2})
        self.assertTrue(rep["reorder_count"] >= 1)
        self.assertTrue(rep["window_ok"])

    def test_empty_and_bad_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "exp.jsonl"
            p.write_text('{"seq": 1}\nnot json\n{"seq": 3}\n', encoding="utf-8")
            text = p.read_text(encoding="utf-8")
            records, bad = lens.parse_jsonl(text)
            self.assertEqual(bad, 1)
            rep = lens.analyze_sequence(records, wait_window=1)
            self.assertEqual(rep["gaps"], [[2, 2]])
            self.assertEqual(rep["coverage"], 0.6667)

    def test_window_flag(self):
        records = [{"seq": 1}, {"seq": 20}]
        rep = lens.analyze_sequence(records, wait_window=10)
        self.assertFalse(rep["window_ok"])
        self.assertEqual(rep["largest_gap"], 18)


class TestFetchInfo(unittest.TestCase):
    def test_fake_opener(self):
        body = b"hello public mirror"
        def opener(url):
            headers = {"Content-Type": "text/plain; charset=utf-8", "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"}
            return (200, headers, body)
        info = lens.fetch_url_info("https://example.com/mirror/1", opener=opener)
        self.assertTrue(info["ok"])
        self.assertEqual(info["status"], 200)
        self.assertEqual(info["charset"], "utf-8")
        self.assertEqual(info["body_len"], len(body))
        want = hashlib.sha256(body).hexdigest()
        self.assertEqual(info["sha256"], want)

    def test_bad_scheme(self):
        info = lens.fetch_url_info("ftp://example.com/x")
        self.assertFalse(info["ok"])
        self.assertEqual(info["status"], 0)


class TestLint(unittest.TestCase):
    def test_find_dids(self):
        good = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        text = "author " + good + " posted"
        found = lens.find_dids(text)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["ok"])
        bad = lens.find_dids("did:key:z00O0 short did:key:zAB")
        for item in bad:
            self.assertFalse(item["ok"])

    def test_checkin_ok_and_bad(self):
        good_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        obj = {
            "type": "agent.checkin.v1",
            "did": good_did,
            "seq": 7,
            "ts": "2024-01-02T03:04:05Z",
            "note": "continuity check",
        }
        self.assertEqual(lens.lint_checkin(obj), [])
        bad = {"type": "other", "did": "nope", "seq": -1, "ts": "bad"}
        errs = lens.lint_checkin(bad)
        self.assertTrue(len(errs) >= 3)


class TestBundleAndClarity(unittest.TestCase):
    def test_bundle_deterministic(self):
        rep = lens.analyze_sequence([{"seq": 1}, {"seq": 3}], wait_window=10)
        urls = [
            {"url": "https://example.com/b", "status": 200, "charset": "utf-8", "last_modified": "", "body_len": 3, "sha256": "aaa"},
            {"url": "https://example.com/a", "status": 404, "charset": "", "last_modified": "", "body_len": 0, "sha256": "bbb"},
        ]
        summary = [{"name": "c1", "errors": []}]
        first = lens.build_evidence_bundle("t", rep, urls, summary, "n")
        second = lens.build_evidence_bundle("t", rep, urls, summary, "n")
        self.assertEqual(first, second)
        self.assertIn("missing 2", first)
        self.assertIn("sha256", first)
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "bundle.md"
            out.write_text(first, encoding="utf-8")
            self.assertTrue(out.read_text(encoding="utf-8").startswith("# t"))

    def test_clarity_flags_long_and_terms(self):
        long_sentence = "This is a very long sentence " + "word " * 30 + "."
        thread = long_sentence + "\nfetch with wait=10 and seq cursor\nSee `MYSTERY_TOKEN` please.\n"
        rep = lens.clarity_report(thread, glossary={"seq"})
        self.assertEqual(rep["sentence_count"] >= 2, True)
        self.assertEqual(len(rep["long_sentences"]), 1)
        self.assertTrue(any("fetch" in s for s in rep["snippets"]))
        self.assertIn("MYSTERY_TOKEN", rep["undefined_terms"])


if __name__ == "__main__":
    unittest.main()
