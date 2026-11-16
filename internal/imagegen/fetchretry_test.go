package imagegen

import "testing"

func TestTransientFetchOnlyNamesNetworkFailures(t *testing.T) {
	for _, c := range []struct {
		out  string
		want bool
	}{
		{"pkg: https://pkgmir.example.net/x.pkg: No route to host", true},
		{"pkg: http://pkg.example.net/meta.txz: Operation timed out", true},
		{"pkg: Temporary failure in name resolution", true},
		{"pkg: http://x/y: HTTP error 503", true},
		{"pkg: Checksum mismatch for FreeBSD-rc", false},
		{"pkg: No packages available to install matching 'nothing'", false},
		{"pkg: Unknown option -z", false},
	} {
		if got := transientFetch([]byte(c.out)); got != c.want {
			t.Errorf("%q: %v, want %v", c.out, got, c.want)
		}
	}
}
