package api

import "testing"

func TestImageNameForRelease(t *testing.T) {
	for in, want := range map[string]string{
		"15.1-RELEASE": "freebsd-15-1", "15.2-RELEASE-p3": "freebsd-15-2", "16.0-CURRENT": "freebsd-16-0",
		"15.1": "freebsd-15-1", "": "", "RELEASE": "", "3.x-RELEASE": "", "15.-RELEASE": "",
	} {
		if got := ImageNameForRelease(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestImageCreateHint(t *testing.T) {
	if got := ImageCreateHint("the base image", "", "", "15.2-RELEASE"); got != "create the base image with 'jailops image create freebsd-15-2 --release 15.2-RELEASE', then build it with 'jailops image build freebsd-15-2' (the console's Images page does both with Create image)" {
		t.Fatal(got)
	}
	if got := ImageCreateHint("it", "base", "lts", ""); got != "create it with 'jailops image create base --release 15.1-RELEASE --alias lts', then build it with 'jailops image build base' (the console's Images page does both with Create image)" {
		t.Fatal(got)
	}
}
