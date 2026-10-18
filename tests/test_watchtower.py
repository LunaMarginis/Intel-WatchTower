"""Unit tests on synthetic exports (no network). Run: python -m unittest discover -s tests -v"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchtower import analyze, checks as C, export, parse, run, store

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
TF_HEADER = "# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, malware_alias, malware_printable, last_seen_utc, confidence_level, is_compromised, reference, tags, anonymous, reporter"
UH_HEADER = "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter"


def md5(i: int) -> str:
    return f"{i:032x}"


def tf_row(i: int, when: datetime, fam: str = "win.vidar", printable: str = "Vidar", alias: str = "None", conf: str = "95", reporter: str = "Grim") -> str:
    q = lambda v: f'"{v}"'
    return ", ".join(q(v) for v in (when.strftime("%Y-%m-%d %H:%M:%S"), 1000 + i, md5(i), "md5_hash", "payload", fam, alias, printable, "None", conf, 0, "None", "None", 0, reporter))


def tf_file(rows: list[str]) -> str:
    return "\n".join(["################", "# ThreatFox IOCs", TF_HEADER, *rows]) + "\n"


def uh_row(i: int, url: str, status: str = "online", tags: str = "elf,Mozi", when: datetime = NOW - timedelta(hours=2)) -> str:
    return f'"{i}","{when.strftime("%Y-%m-%d %H:%M:%S")}","{url}","{status}","{when.strftime("%Y-%m-%d %H:%M:%S")}","malware_download","{tags}","https://urlhaus.abuse.ch/url/{i}/","reporter1"'


def uh_file(rows: list[str]) -> str:
    return "\n".join(["################", UH_HEADER, *rows]) + "\n"


def fixtures(n_hash: int = 12, n_url: int = 1500):
    tf = tf_file([tf_row(i, NOW - timedelta(hours=1, minutes=i), alias="Alias A,Alias B" if i % 3 == 0 else "None") for i in range(n_hash)])
    uh = uh_file([uh_row(i, f"http://203.0.113.{i % 250}/p{i}.sh" if i % 2 else f"http://bad{i}.example.net/x#frag{i}", "online" if i % 3 else "offline", "elf,Mozi" if i % 4 else "") for i in range(n_url)])
    return tf, uh


class ParseTests(unittest.TestCase):
    def test_header_and_comma_space_quotes(self):
        ex = parse.parse_export(tf_file([tf_row(1, NOW)]))
        self.assertEqual(ex.header[2], "ioc_value")
        self.assertEqual(len(ex.rows), 1)
        self.assertEqual(ex.rows[0]["ioc_value"], md5(1))
        self.assertEqual(ex.skipped, [])

    def test_placeholder_none_becomes_empty_and_alias_kept(self):
        hs, rej = parse.threatfox_records(parse.parse_export(tf_file([tf_row(1, NOW), tf_row(2, NOW, alias="X,Y")])))
        self.assertEqual(rej, [])
        by = {h.ioc_value: h for h in hs}
        self.assertEqual(by[md5(1)].alias, "")
        self.assertEqual(by[md5(2)].alias, "X,Y")

    def test_bad_hash_is_rejected_not_dropped_silently(self):
        bad = tf_row(3, NOW).replace(md5(3), "not-a-hash")
        hs, rej = parse.threatfox_records(parse.parse_export(tf_file([tf_row(1, NOW), bad])))
        self.assertEqual(len(hs), 1)
        self.assertEqual(len(rej), 1)

    def test_hash_in_url_fragment_survives(self):
        ex = parse.parse_export(uh_file([uh_row(1, "http://a.example/x#y#z")]))
        urls, rej = parse.urlhaus_records(ex)
        self.assertEqual(urls[0].url, "http://a.example/x#y#z")

    def test_untagged_url_is_kept(self):
        urls, _ = parse.urlhaus_records(parse.parse_export(uh_file([uh_row(1, "http://a.example/", tags="")])))
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0].tags, [])

    def test_defang(self):
        self.assertEqual(parse.defang_url("http://a.b.c:8080/x"), "http[:]//a[.]b[.]c[:]8080/x")
        self.assertEqual(parse.defang_host("1.2.3.4"), "1[.]2[.]3[.]4")


class ChecksTests(unittest.TestCase):
    def test_overall_takes_worst(self):
        self.assertEqual(C.overall([C.Check("a", C.PASS, ""), C.Check("b", C.WARN, "")]), C.WARN)
        self.assertEqual(C.overall([C.Check("a", C.WARN, ""), C.Check("b", C.FAIL, "")]), C.FAIL)

    def test_missing_column_fails(self):
        ex = parse.parse_export(tf_file([tf_row(1, NOW)]))
        self.assertEqual(C.columns("t", ex, parse.THREATFOX_REQUIRED).status, C.PASS)
        self.assertEqual(C.columns("t", ex, parse.THREATFOX_REQUIRED + ["brand_new_required"]).status, C.FAIL)

    def test_volume_and_freshness(self):
        self.assertEqual(C.volume("t", 0, 5, None).status, C.FAIL)
        self.assertEqual(C.volume("t", 100, 5, 100).status, C.PASS)
        self.assertEqual(C.volume("t", 10, 5, 100).status, C.WARN)
        self.assertEqual(C.freshness("t", NOW - timedelta(hours=1), NOW, 24, 72).status, C.PASS)
        self.assertEqual(C.freshness("t", NOW - timedelta(hours=30), NOW, 24, 72).status, C.WARN)
        self.assertEqual(C.freshness("t", NOW - timedelta(hours=100), NOW, 24, 72).status, C.FAIL)
        self.assertEqual(C.freshness("t", None, NOW, 24, 72).status, C.FAIL)

    def test_live_url_in_output_is_a_failure(self):
        self.assertEqual(C.defanged("x", "see hxxp and example[.]com").status, C.PASS)
        self.assertEqual(C.defanged("x", "visit http://evil.example/payload now").status, C.FAIL)
        self.assertEqual(C.defanged("x", "docs at https://github.com/LunaMarginis/Intel-WatchTower ok").status, C.PASS)


class AnalyzeStoreExportTests(unittest.TestCase):
    def setUp(self):
        tf, uh = fixtures()
        self.hashes, _ = parse.threatfox_records(parse.parse_export(tf))
        self.urls, _ = parse.urlhaus_records(parse.parse_export(uh))

    def test_sparkline_and_arrow(self):
        self.assertEqual(len(analyze.sparkline([0, 1, 5, 2])), 4)
        self.assertIn("new", analyze.arrow(5, 0).lower())

    def test_archive_accumulates_and_prunes(self):
        arc, added = store.merge_archive({}, self.hashes, NOW)
        self.assertEqual(added, len(self.hashes))
        arc, added = store.merge_archive(arc, self.hashes, NOW)
        self.assertEqual(added, 0)
        old = parse.Hash(md5(999), NOW - timedelta(days=store.ARCHIVE_DAYS + 5), "1", "payload", "win.x", "", "X", 90, [], "", "r")
        arc, _ = store.merge_archive({old.ioc_value: old}, [], NOW)
        self.assertEqual(arc, {})

    def test_archive_round_trip(self):
        arc, _ = store.merge_archive({}, self.hashes, NOW)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.csv"
            store.write_text(p, store.archive_text(arc))
            self.assertEqual(set(store.load_archive(p)), set(arc))
            self.assertFalse(store.write_text(p, store.archive_text(arc)), "unchanged content must not rewrite the file")

    def test_hash_summary(self):
        s = analyze.hash_summary(self.hashes, self.hashes, set(), NOW)
        self.assertEqual(s["in_export"], len(self.hashes))
        self.assertEqual(s["new_this_run"], len(self.hashes))
        s2 = analyze.hash_summary(self.hashes, self.hashes, {h.ioc_value for h in self.hashes}, NOW)
        self.assertEqual(s2["new_this_run"], 0)

    def test_url_summary_counts_tags_individually(self):
        s = analyze.url_summary(self.urls, set(), NOW)
        tags = dict(s["tags"])
        self.assertIn("elf", tags)
        self.assertIn("Mozi", tags)
        self.assertEqual(s["total"], len(self.urls))
        self.assertGreater(s["untagged"], 0)

    def test_feeds_are_deterministic_and_defanged(self):
        arc = list(self.hashes)
        self.assertEqual(export.md5_feed(arc, NOW, 7), export.md5_feed(arc, NOW, 7))
        hosts = export.hosts_feed(self.urls)
        self.assertNotIn("203.0.113.1\n", hosts)
        self.assertIn("[.]", hosts)

    def test_stix_bundle_is_valid_shape_and_stable(self):
        b1, b2 = export.stix_bundle(self.hashes, NOW), export.stix_bundle(self.hashes, NOW)
        self.assertEqual(export.stix_text(b1), export.stix_text(b2))
        ids = [o["id"] for o in b1["objects"]]
        self.assertEqual(len(ids), len(set(ids)))
        inds = [o for o in b1["objects"] if o["type"] == "indicator"]
        self.assertEqual(len(inds), len(self.hashes))
        self.assertTrue(all(o["pattern"].startswith("[file:hashes.MD5 = '") for o in inds))
        for o in b1["objects"]:
            if o["type"] == "relationship":
                self.assertIn(o["source_ref"], ids)
                self.assertIn(o["target_ref"], ids)

    def test_safe_text_strips_markup(self):
        for ch in "|`<>[]\"'*":
            self.assertNotIn(ch, export.safe_text(f"a{ch}b"))


class EndToEndTests(unittest.TestCase):
    def _run(self, root: Path, off: Path, now: datetime = NOW, **kw) -> int:
        return run.run(root, offline=off, now=now, log=lambda *_: None, **kw)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root, self.off = Path(self.tmp.name) / "repo", Path(self.tmp.name) / "in"
        self.off.mkdir()
        tf, uh = fixtures()
        (self.off / "tf.csv").write_text(tf, encoding="utf-8")
        (self.off / "uh.csv").write_text(uh, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_run_writes_everything(self):
        self.assertIn(self._run(self.root, self.off), (0,))  # warnings (no export stamp in fixtures) do not fail the run
        for rel in ("README.md", "mhash.csv", "urls.csv", "data/hashes_archive.csv", "feeds/md5_7d.txt", "feeds/hosts_online.txt", "feeds/stix_md5_7d.json", "feeds/iocs.json", "history/runs.jsonl", "reports/2026-10-18.md"):
            self.assertTrue((self.root / rel).exists(), rel)
        json.loads((self.root / "feeds/stix_md5_7d.json").read_text(encoding="utf-8"))
        self.assertNotIn("http://", (self.root / "urls.csv").read_text(encoding="utf-8"))

    def test_second_run_leaves_data_files_untouched_and_skips_url_refresh(self):
        self._run(self.root, self.off)
        before = {p: p.read_bytes() for p in (self.root / "mhash.csv", self.root / "urls.csv", self.root / "data/hashes_archive.csv", self.root / "feeds/md5_7d.txt")}
        self._run(self.root, self.off, now=NOW + timedelta(hours=6))
        for p, b in before.items():
            self.assertEqual(p.read_bytes(), b, p.name)
        self.assertEqual(len((self.root / "history/runs.jsonl").read_text(encoding="utf-8").splitlines()), 2)

    def test_broken_download_keeps_previous_data_and_fails(self):
        self._run(self.root, self.off)
        good = (self.root / "mhash.csv").read_bytes()
        (self.off / "tf.csv").write_text("<html>Service unavailable</html>\n", encoding="utf-8")
        rc = self._run(self.root, self.off, now=NOW + timedelta(hours=6))
        self.assertEqual(rc, 1)
        self.assertEqual((self.root / "mhash.csv").read_bytes(), good)
        self.assertIn("columns", (self.root / "README.md").read_text(encoding="utf-8"))

    def test_hash_archive_keeps_hashes_that_left_the_export(self):
        self._run(self.root, self.off)
        (self.off / "tf.csv").write_text(tf_file([tf_row(500 + i, NOW + timedelta(hours=5, minutes=i)) for i in range(12)]), encoding="utf-8")
        self._run(self.root, self.off, now=NOW + timedelta(hours=6))
        arc = store.load_archive(self.root / "data/hashes_archive.csv")
        self.assertEqual(len(arc), 24)

    def test_no_third_party_markup_reaches_the_readme(self):
        (self.off / "tf.csv").write_text(tf_file([tf_row(1, NOW - timedelta(hours=1), fam="win.x", printable="Evil|[click](http://evil.example/)<script>", reporter="`bad`")]), encoding="utf-8")
        self._run(self.root, self.off)
        text = (self.root / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("http://evil", text)
        self.assertNotIn("<script", text)


if __name__ == "__main__":
    unittest.main()
