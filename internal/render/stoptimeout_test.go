package render

import (
	"strings"
	"testing"
)

// stop.timeout is the jail's own time to shut down, written after exec.stop only when the jail asked for one.
func TestJailConfStopTimeout(t *testing.T) {
	in := baseConf()
	s, err := JailConf(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "stop.timeout") {
		t.Errorf("a jail without a stop timeout has one:\n%s", s)
	}
	in.StopTimeout = 45
	s, err = JailConf(in)
	if err != nil {
		t.Fatal(err)
	}
	stop := strings.Index(s, "\texec.stop = ")
	to := strings.Index(s, "\tstop.timeout = 45;\n")
	if stop < 0 || to < stop {
		t.Errorf("stop.timeout must follow exec.stop:\n%s", s)
	}
}
