"""Unit tests on synthetic exports (no network). Run: python -m unittest discover -s tests -v"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchtower import analyze, checks as C, export, indicators, parse, run, store

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

    def test_hash_records_accumulate_dedupe_and_prune(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            files, new = indicators.add_hashes(root, {}, self.hashes, NOW)
            self.assertEqual(len(new), len(self.hashes))
            for p, t in files.items():
                store.write_text(p, t)
            known = indicators.load_hashes(root, NOW)
            self.assertEqual(set(known), {h.ioc_value for h in self.hashes})
            files2, new2 = indicators.add_hashes(root, known, self.hashes, NOW)
            self.assertEqual((files2, new2), ({}, []), "a second pass with the same hashes must write nothing")
            old = root / indicators.HASH_DIR / "2020-01-01.jsonl"
            old.write_text("{}\n", encoding="utf-8")
            self.assertEqual(indicators.prune(root, indicators.HASH_DIR, NOW, indicators.HASH_KEEP_DAYS), 1)

    def test_hash_record_is_enriched_and_round_trips(self):
        h = self.hashes[3]
        r = indicators.hash_record(h, NOW)
        for key in ("schema", "kind", "algo", "value", "source", "first_seen", "collected_at", "age_at_collection_h", "family", "aliases", "confidence", "reporter"):
            self.assertIn(key, r)
        back = indicators.hash_from_record(json.loads(indicators.jsonl_text([r])))
        self.assertEqual((back.ioc_value, back.first_seen, back.family, back.confidence), (h.ioc_value, h.first_seen.replace(microsecond=0), h.family, h.confidence))

    def test_url_records_only_for_new_recent_or_changed_and_are_defanged(self):
        fam = indicators.family_names(self.hashes)
        self.assertIn("vidar", fam)
        prev = {u.id: u.status for u in self.urls}
        flip = self.urls[0]
        prev[flip.id] = "offline" if flip.status == "online" else "online"
        del prev[self.urls[1].id]
        with tempfile.TemporaryDirectory() as d:
            files, n_new, n_changed = indicators.add_urls(Path(d), prev, self.urls, fam, NOW)
            self.assertEqual((n_new, n_changed), (1, 1))
            recs = [json.loads(line) for text in files.values() for line in text.splitlines()]
            self.assertEqual({r["change"] for r in recs}, {"new", "status_changed"})
            self.assertTrue(all("http://" not in r["url"] and r["schema"] == 1 for r in recs))
            old = parse.Url("9", NOW - timedelta(days=10), "http://old.example/", "online", "malware_download", [], "r", "old.example", False, "")
            self.assertEqual(indicators.add_urls(Path(d), {}, [old], fam, NOW)[1], 0, "old backlog URLs are not turned into records")

    def test_url_tag_links_family_as_inferred(self):
        u = parse.Url("5", NOW, "http://a.example/x", "online", "malware_download", ["Vidar", "zip"], "r", "a.example", False, "")
        with tempfile.TemporaryDirectory() as d:
            files, _, _ = indicators.add_urls(Path(d), {}, [u], indicators.family_names(self.hashes), NOW)
            rec = json.loads(next(iter(files.values())).splitlines()[0])
            self.assertEqual(rec["related_families"], ["Vidar"])

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
        for rel in ("README.md", "mhash.csv", "urls.csv", "indicators/hashes/2026-10-18.jsonl", "feeds/md5_7d.txt", "feeds/hosts_online.txt", "feeds/stix_md5_7d.json", "feeds/iocs.json", "history/runs.jsonl", "reports/2026-10-18.md"):
            self.assertTrue((self.root / rel).exists(), rel)
        json.loads((self.root / "feeds/stix_md5_7d.json").read_text(encoding="utf-8"))
        self.assertNotIn("http://", (self.root / "urls.csv").read_text(encoding="utf-8"))

    def test_second_run_leaves_data_files_untouched_and_skips_url_refresh(self):
        self._run(self.root, self.off)
        before = {p: p.read_bytes() for p in (self.root / "mhash.csv", self.root / "urls.csv", *(self.root / "indicators/hashes").glob("*.jsonl"), self.root / "feeds/md5_7d.txt")}
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
        arc = indicators.load_hashes(self.root, NOW + timedelta(hours=6))
        self.assertEqual(len(arc), 24)

    def test_past_days_never_change_and_url_changes_are_recorded(self):
        self._run(self.root, self.off)
        day1 = (self.root / "indicators/hashes/2026-10-18.jsonl").read_bytes()
        url1 = (self.root / "indicators/urls/2026-10-18.jsonl").read_bytes()
        later = NOW + timedelta(days=1)
        (self.off / "tf.csv").write_text(tf_file([tf_row(700 + i, later - timedelta(hours=1, minutes=i)) for i in range(12)]), encoding="utf-8")
        flipped = uh_file([uh_row(i, f"http://203.0.113.{i % 250}/p{i}.sh" if i % 2 else f"http://bad{i}.example.net/x#frag{i}", "offline", "elf,Mozi", later - timedelta(hours=2)) for i in range(1500)])
        (self.off / "uh.csv").write_text(flipped, encoding="utf-8")
        self._run(self.root, self.off, now=later)
        self.assertEqual((self.root / "indicators/hashes/2026-10-18.jsonl").read_bytes(), day1)
        self.assertEqual((self.root / "indicators/urls/2026-10-18.jsonl").read_bytes(), url1)
        changes = [json.loads(line) for line in (self.root / "indicators/urls/2026-10-19.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertTrue(changes and all(c["change"] == "status_changed" and c["status"] == "offline" for c in changes))
        self.assertEqual(len(list((self.root / "indicators/hashes").glob("*.jsonl"))), 2)

    def test_no_third_party_markup_reaches_the_readme(self):
        (self.off / "tf.csv").write_text(tf_file([tf_row(1, NOW - timedelta(hours=1), fam="win.x", printable="Evil|[click](http://evil.example/)<script>", reporter="`bad`")]), encoding="utf-8")
        self._run(self.root, self.off)
        text = (self.root / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("http://evil", text)
        self.assertNotIn("<script", text)


if __name__ == "__main__":
    unittest.main()
