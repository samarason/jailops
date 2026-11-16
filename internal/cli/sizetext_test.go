package cli

import "testing"

// Sizes come back from the server as bytes; they are shown in the unit they were most likely given in.
func TestSizeText(t *testing.T) {
	for in, want := range map[string]string{
		"4294967296": "4G", "536870912": "512M", "1024": "1K", "1610612736": "1536M", "17592186044416": "16T",
		"7": "7", "1000": "1000", "0": "0", "4G": "4G", "": "",
	} {
		if got := sizeText(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
