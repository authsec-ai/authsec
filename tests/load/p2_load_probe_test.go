package load

import (
	"os"
	"strings"
	"testing"
)

func TestP2LoadProbe(t *testing.T) {
	env := loadEnvFor(t)
	want := os.Getenv("LOAD_PROBE")
	for _, c := range loadCases(t, env) {
		if !strings.Contains(c.name, want) || (os.Getenv("LOAD_SKIP") != "" && strings.Contains(c.name, os.Getenv("LOAD_SKIP"))) {
			continue
		}
		r := loadMeasure(env.api, c, 15)
		flag := ""
		for _, row := range c.rows {
			if r.p95 > loadTargets[row] {
				flag = " MISS " + row
			}
		}
		t.Logf("%-62s p50 %7.1f p95 %7.1f max %7.1f cnt %6.1f slow %6.1f%s %v", c.name, loadMS(r.p50), loadMS(r.p95), loadMS(r.max), loadMS(r.counts), loadMS(r.slowest[0].elapsed), flag, r.fails)
	}
}
