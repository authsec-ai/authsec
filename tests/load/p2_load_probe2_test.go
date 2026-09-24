package load

import (
	"os"
	"strings"
	"testing"
)

func TestP2LoadProbeSQL(t *testing.T) {
	env := loadEnvFor(t)
	want := os.Getenv("LOAD_PROBE")
	for _, c := range loadCases(t, env) {
		if c.name != want {
			continue
		}
		path := c.path(0)
		loadTracer.start()
		code, _, d := env.api.get(path)
		stmts := loadTracer.stop()
		t.Logf("%s %d %.1f ms", c.name, code, loadMS(d))
		for i, s := range stmts {
			if i >= 6 {
				break
			}
			t.Logf("  %.1f ms %s", loadMS(s.elapsed), loadClipSQL(s.sql)[:80])
			_ = os.WriteFile(os.Getenv("LOAD_PROBE_OUT")+"_"+string(rune('0'+i))+".sql", []byte(s.sql), 0o644)
		}
	}
	_ = strings.Contains
}
