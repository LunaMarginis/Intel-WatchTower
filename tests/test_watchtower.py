"""Unit tests on synthetic exports (no network). Run: python -m unittest discover -s tests -v"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchtower import analyze, checks as C, export, indicators, parse, platforms, run, store

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


def infra_row(value: str, kind: str, when: datetime, threat: str = "botnet_cc", fam: str = "win.vidar", printable: str = "Vidar", i: int = 0) -> str:
    q = lambda v: f'"{v}"'
    return ", ".join(q(v) for v in (when.strftime("%Y-%m-%d %H:%M:%S"), 5000 + i, value, kind, threat, fam, "None", printable, "", "100", "False", "None", "vidar,c2", 0, "reporter1"))


def infra_file(rows: list[str]) -> str:
    return "\n".join(["################", "# Last updated: " + NOW.strftime("%Y-%m-%d %H:%M:%S") + " UTC", TF_HEADER, *rows]) + "\n"


class InfraTests(unittest.TestCase):
    def test_domains_are_validated(self):
        ex = parse.parse_export(infra_file([infra_row("Evil.Example.com.", "domain", NOW), infra_row("not a domain", "domain", NOW, i=1), infra_row("1.2.3.4:80", "ip:port", NOW, i=2)]))
        items, rej = parse.infra_records(ex, "domain")
        self.assertEqual([i.value for i in items], ["evil.example.com"])
        self.assertEqual(len(rej), 2)

    def test_ip_port_rows_of_one_ip_become_one_entry_with_ports(self):
        rows = [infra_row("10.0.0.5:443", "ip:port", NOW, i=1), infra_row("10.0.0.5:80", "ip:port", NOW - timedelta(hours=1), i=2), infra_row("999.1.1.1:80", "ip:port", NOW, i=3), infra_row("10.0.0.6:99999", "ip:port", NOW, i=4)]
        items, rej = parse.infra_records(parse.parse_export(infra_file(rows)), "ip")
        self.assertEqual(len(items), 1)
        self.assertEqual((items[0].value, items[0].ports, items[0].first_seen), ("10.0.0.5", [80, 443], NOW - timedelta(hours=1)))
        self.assertEqual(len(rej), 2)

    def test_dataset_records_are_defanged_round_trip_and_deduped(self):
        items, _ = parse.infra_records(parse.parse_export(infra_file([infra_row("c2.example.net", "domain", NOW)])), "domain")
        ips, _ = parse.infra_records(parse.parse_export(infra_file([infra_row("10.0.0.5:443", "ip:port", NOW, i=1)])), "ip")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            files, new = indicators.add_infra(root, {}, items + ips, NOW)
            self.assertEqual(len(new), 2)
            text = next(iter(files.values()))
            self.assertIn("c2[.]example[.]net", text)
            self.assertNotIn("c2.example.net", text)
            for p, t in files.items():
                store.write_text(p, t)
            known = indicators.load_infra(root, NOW)
            self.assertEqual(set(known), {"domain:c2.example.net", "ip:10.0.0.5"})
            self.assertEqual(known["ip:10.0.0.5"].ports, [443])
            self.assertEqual(indicators.add_infra(root, known, items + ips, NOW), ({}, []))
            old = parse.Infra("domain", "ancient.example", NOW - timedelta(days=indicators.INFRA_KEEP_DAYS + 3), "1", "botnet_cc", "", "", "X", 90)
            self.assertEqual(indicators.add_infra(root, known, [old], NOW), ({}, []), "entries older than the retention window are not re-added on every run")

    def test_overlap_with_urlhaus_and_feed(self):
        ips, _ = parse.infra_records(parse.parse_export(infra_file([infra_row("10.0.0.5:443", "ip:port", NOW, i=1)])), "ip")
        doms, _ = parse.infra_records(parse.parse_export(infra_file([infra_row("quiet.example", "domain", NOW, i=2), infra_row("busy.example", "domain", NOW, i=3, threat="payload_delivery")])), "domain")
        hosts = {"10.0.0.5": [7, 3], "busy.example": [2, 2], "unrelated.example": [9, 9]}
        ov = analyze.infra_overlap(ips + doms, hosts)
        self.assertEqual([(o["value"], o["urls"], o["online"]) for o in ov], [("10.0.0.5", 7, 3), ("busy.example", 2, 2)])
        feed = export.infra_feed(ips + doms, "domain", NOW, 7)
        self.assertIn("quiet[.]example", feed)
        self.assertNotIn("busy", feed, "only command-and-control entries go into the C2 list")

    def test_url_hosts_are_read_back_from_the_defanged_csv(self):
        urls = [parse.Url("1", NOW, "http://10.0.0.5:8080/a", "online", "malware_download", [], "r", "10.0.0.5", True, ""),
                parse.Url("2", NOW, "http://Busy.Example/b?x=1#f", "offline", "malware_download", [], "r", "busy.example", False, "")]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "urls.csv"
            store.write_text(p, store.urls_text(urls))
            self.assertEqual(store.url_hosts(p), {"10.0.0.5": [1, 1], "busy.example": [1, 0]})

    def test_url_summary_lists_domains_and_ips_separately(self):
        def u(i, host):
            return parse.Url(str(i), NOW - timedelta(hours=1), f"http://{host}/f", "online", "malware_download", [], "r", host, host.replace(".", "").isdigit(), "")
        s = analyze.url_summary([u(1, "203.0.113.9"), u(2, "203.0.113.9"), u(3, "bad.example.net"), u(4, "raw.githubusercontent.com")], set(), NOW)
        self.assertEqual(s["domains"], [("bad.example.net", 1)])
        self.assertEqual(s["ips"], [("203.0.113.9", 2)])
        self.assertEqual((s["unique_domains"], s["unique_ips"]), (1, 1))


class PlatformTests(unittest.TestCase):
    def test_platform_matching(self):
        p = platforms.platform_of
        self.assertEqual(p("raw.githubusercontent.com"), "GitHub")
        self.assertEqual(p("GitHub.com"), "GitHub")
        self.assertEqual(p("evil.blob.core.windows.net"), "Azure Blob Storage")
        self.assertEqual(p("cdn.discordapp.com:443"), "Discord")
        self.assertEqual(p("my-app.pages.dev."), "Cloudflare Pages")

    def test_lookalikes_and_ips_are_not_platforms(self):
        p = platforms.platform_of
        for host in ("notgithub.com", "github.com.evil.example", "githubusercontent.com.evil.net", "evil-dropbox.com", "203.0.113.7", "", "dropbox"):
            self.assertIsNone(p(host), host)

    def test_summary_separates_platforms_from_own_infrastructure(self):
        def u(i, host, status="online"):
            return parse.Url(str(i), NOW - timedelta(hours=1), f"http://{host}/f{i}", status, "malware_download", ["elf"], "r", host, host.replace(".", "").isdigit(), "")
        urls = [u(1, "raw.githubusercontent.com"), u(2, "raw.githubusercontent.com"), u(3, "cdn.discordapp.com"), u(4, "bad.example.net"), u(5, "203.0.113.9"), u(6, "203.0.113.9", "offline")]
        s = analyze.url_summary(urls, set(), NOW)
        self.assertEqual([h for h, _ in s["hosts"]], ["203.0.113.9", "bad.example.net"])
        self.assertEqual(dict(s["hosts_online"]), {"203.0.113.9": 1, "bad.example.net": 1})
        self.assertEqual(dict(s["platforms"]), {"GitHub": 2, "Discord": 1})
        self.assertEqual((s["platform_urls"], s["platform_share"], s["unique_hosts"]), (3, 50, 2))
        feed = export.hosts_feed(urls)
        self.assertNotIn("github", feed)
        self.assertIn("bad[.]example[.]net", feed)


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

    def test_summary_saved_by_an_older_version_is_refreshed_not_rendered(self):
        self._run(self.root, self.off)
        path = self.root / "feeds/iocs.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        for key in ("platforms", "platforms_online", "platform_urls", "platform_share"):
            del saved["urls"][key]          # what the previous release wrote
        path.write_text(json.dumps(saved), encoding="utf-8")
        self.assertEqual(self._run(self.root, self.off, now=NOW + timedelta(hours=6)), 0, "must not crash, and must not wait a day to refresh")
        again = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("platform_share", again["urls"])
        self.assertIn("Abused platforms", (self.root / "README.md").read_text(encoding="utf-8"))

    def test_infrastructure_section_files_and_overlap(self):
        doms = [infra_row("c2.example.net", "domain", NOW - timedelta(hours=1), i=1), infra_row("drop.example.org", "domain", NOW - timedelta(hours=2), "payload_delivery", i=2)]
        doms += [infra_row(f"extra{n}.example.net", "domain", NOW - timedelta(hours=3), i=20 + n) for n in range(4)]
        ips = [infra_row("203.0.113.5:443", "ip:port", NOW - timedelta(hours=1), i=3), infra_row("203.0.113.5:80", "ip:port", NOW - timedelta(hours=1), i=4)]
        ips += [infra_row(f"198.51.100.{n}:443", "ip:port", NOW - timedelta(hours=3), i=40 + n) for n in range(1, 6)]
        (self.off / "tfd.csv").write_text(infra_file(doms), encoding="utf-8")
        (self.off / "tfi.csv").write_text(infra_file(ips), encoding="utf-8")
        self.assertEqual(self._run(self.root, self.off), 0)
        for rel in ("feeds/c2_domains_7d.txt", "feeds/c2_ips_7d.txt", "indicators/infra/2026-10-18.jsonl"):
            self.assertTrue((self.root / rel).exists(), rel)
        readme = (self.root / "README.md").read_text(encoding="utf-8")
        self.assertIn("Command-and-control infrastructure", readme)
        self.assertIn("c2[.]example[.]net", readme)
        self.assertNotIn("c2.example.net", readme)
        state = json.loads((self.root / "feeds/iocs.json").read_text(encoding="utf-8"))
        self.assertEqual((state["infra"]["domains"]["in_export"], state["infra"]["ips"]["in_export"]), (6, 6))
        self.assertTrue(any(o["value"] == "203.0.113.5" for o in state["infra"]["overlap"]), "fixture URLs include 203.0.113.5, which ThreatFox calls C2")

    def test_a_broken_infrastructure_download_keeps_previous_infrastructure(self):
        rows = [infra_row(f"d{n}.example.net", "domain", NOW - timedelta(hours=1), i=10 + n) for n in range(6)]
        (self.off / "tfd.csv").write_text(infra_file(rows), encoding="utf-8")
        self._run(self.root, self.off)
        before = (self.root / "feeds/c2_domains_7d.txt").read_bytes()
        (self.off / "tfd.csv").write_text("<html>maintenance</html>\n", encoding="utf-8")
        self.assertEqual(self._run(self.root, self.off, now=NOW + timedelta(hours=6)), 1)
        self.assertEqual((self.root / "feeds/c2_domains_7d.txt").read_bytes(), before)

    def test_no_third_party_markup_reaches_the_readme(self):
        (self.off / "tf.csv").write_text(tf_file([tf_row(1, NOW - timedelta(hours=1), fam="win.x", printable="Evil|[click](http://evil.example/)<script>", reporter="`bad`")]), encoding="utf-8")
        self._run(self.root, self.off)
        text = (self.root / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("http://evil", text)
        self.assertNotIn("<script", text)


if __name__ == "__main__":
    unittest.main()
