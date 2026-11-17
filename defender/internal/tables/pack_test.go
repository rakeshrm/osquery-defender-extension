package tables

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every pack query must select only columns its table declares.
func TestPackColumnsExist(t *testing.T) {
	b, err := os.ReadFile("../../../pack/defender_mpengine.conf")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Queries map[string]struct{ Query string } `json:"queries"`
	}
	if err := json.Unmarshal(b, &pack); err != nil {
		t.Fatal(err)
	}
	cols := map[string][]string{}
	for _, d := range testConfig(t).defs() {
		for _, c := range d.cols {
			cols[d.name] = append(cols[d.name], c.Name)
		}
	}
	re := regexp.MustCompile(`(?is)^SELECT (.+?) FROM (\w+)(?: WHERE (.+?))?;$`)
	ident := regexp.MustCompile(`\b[a-z_][a-z0-9_]*\b`)
	keywords := []string{"and", "or", "not", "like", "in", "is", "null", "group", "by", "order", "desc", "asc", "limit"}
	for name, q := range pack.Queries {
		m := re.FindStringSubmatch(strings.TrimSpace(q.Query))
		if m == nil {
			t.Errorf("%s: unrecognised query shape: %s", name, q.Query)
			continue
		}
		have, ok := cols[m[2]]
		if !ok {
			t.Errorf("%s: unknown table %s", name, m[2])
			continue
		}
		// Ignore string literals in the WHERE clause.
		where := regexp.MustCompile(`'[^']*'`).ReplaceAllString(m[3], "")
		for _, c := range ident.FindAllString(m[1]+" "+where, -1) {
			if !slices.Contains(have, c) && !slices.Contains(keywords, c) {
				t.Errorf("%s: column %s not in %s", name, c, m[2])
			}
		}
	}
}
