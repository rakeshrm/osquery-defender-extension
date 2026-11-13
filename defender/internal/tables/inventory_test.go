package tables

import (
	"reflect"
	"sort"
	"testing"
)

// InventoryEntries schema captured verbatim from a live Defender database
// (engines 1.1.26090.9 / 1.1.26100.4, Windows Server 2022).
const inventoryEntriesDDL = `CREATE TABLE InventoryEntries (  identifier      TEXT PRIMARY KEY,  vulnerabilities TEXT NOT NULL DEFAULT '',  first_seen_utc  INTEGER NOT NULL,  last_seen_utc   INTEGER NOT NULL)`

func TestInventoryEntries(t *testing.T) {
	dir := sqliteDir(t,
		inventoryEntriesDDL,
		`INSERT INTO InventoryEntries VALUES
		  ('cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*', 'CVE-2024-11477', 1793000000, 1793800000),
		  ('pkg:generic/openssl@3.0.1', '["CVE-2023-0286","CVE-2022-3602","CVE-2023-0286"]', 1793100000, 1793900000),
		  ('pkg:nuget/Newtonsoft.Json@12.0.1', 'CVE-2024-21907; CVE-2024-0001 ,CVE-2024-21907', 1793200000, 1793950000),
		  ('cpe:2.3:a:vendor:clean:1.0:*:*:*:*:*:*:*', '', 1793300000, 1793990000)`,
	)
	cfg := testConfig(t)
	rows := genPath(t, cfg, "defender_mpengine_inventory_identifiers", dir)
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4", len(rows))
	}
	got := map[string]map[string]string{}
	for _, r := range rows {
		got[r["identifier"]] = r
	}
	want := map[string][4]string{ // kind_name, vulnerabilities, first_seen, last_seen
		"cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*": {"cpe", "CVE-2024-11477", "1793000000", "1793800000"},
		"pkg:generic/openssl@3.0.1":                 {"purl", "CVE-2022-3602,CVE-2023-0286", "1793100000", "1793900000"},
		"pkg:nuget/Newtonsoft.Json@12.0.1":          {"purl", "CVE-2024-0001,CVE-2024-21907", "1793200000", "1793950000"},
		"cpe:2.3:a:vendor:clean:1.0:*:*:*:*:*:*:*":  {"cpe", "", "1793300000", "1793990000"},
	}
	for id, w := range want {
		r, ok := got[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		g := [4]string{r["kind_name"], r["vulnerabilities"], r["first_seen"], r["last_seen"]}
		if g != w {
			t.Errorf("%s: got %v, want %v", id, g, w)
		}
		if r["source"] != "InventoryEntries" || r["kind"] != "" {
			t.Errorf("%s: source=%q kind=%q", id, r["source"], r["kind"])
		}
	}
}

// Both layouts in one database are unioned, each labelled with its source.
func TestInventoryBothSources(t *testing.T) {
	dir := sqliteDir(t,
		inventoryEntriesDDL,
		`INSERT INTO InventoryEntries VALUES ('pkg:generic/zlib@1.2.11', 'CVE-2022-37434', 1, 2)`,
		`CREATE TABLE MetaInventoryIdentifiers (ID INTEGER PRIMARY KEY, Identifier TEXT, Kind INTEGER)`,
		`INSERT INTO MetaInventoryIdentifiers VALUES (1, 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*', 1)`,
		`CREATE TABLE MetaInventoryIdentifierVulnerabilities (ID INTEGER PRIMARY KEY, Identifier TEXT, VulnerabilityId TEXT)`,
		`INSERT INTO MetaInventoryIdentifierVulnerabilities VALUES (1, 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*', ' CVE-2 '), (2, 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*', 'CVE-1')`,
	)
	rows := genPath(t, testConfig(t), "defender_mpengine_inventory_identifiers", dir)
	var sources []string
	for _, r := range rows {
		sources = append(sources, r["source"]+"|"+r["kind_name"]+"|"+r["vulnerabilities"])
	}
	sort.Strings(sources)
	want := []string{
		"InventoryEntries|purl|CVE-2022-37434",
		"MetaInventoryIdentifiers|cpe|CVE-1,CVE-2",
	}
	if !reflect.DeepEqual(sources, want) {
		t.Errorf("got %v, want %v", sources, want)
	}
}
