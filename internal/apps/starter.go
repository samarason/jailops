package apps

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// StarterOptions are what 'jailops app new' was given.
type StarterOptions struct {
	Name     string
	Packages []string
	Services []string
	// Ports are "N" or "N/proto".
	Ports    []string
	Category string
}

// Starter drafts a new definition: every key present, prefilled from the
// options, with TODO markers where a person has to decide. The result parses
// and validates as it is; an option that cannot be used is an error.
func Starter(o StarterOptions) (Draft, error) {
	if err := validate.Name("name", o.Name); err != nil {
		return Draft{}, fmt.Errorf("%q is not an app name: lower case letters, digits and dashes, starting with a letter, at most 63 characters", o.Name)
	}
	todo := map[string]string{}
	a := api.App{
		Version: 1, Name: o.Name, Title: titleOf(o.Name),
		Summary:     TodoMarker + ": what it is and what it is for, in one line.",
		Description: TodoMarker + ": a few short paragraphs of plain text: what the software does, what this\ndefinition sets up and what is left to the operator.\n",
		Category:    api.AppOther,
		Homepage:    "https://example.com/",
		License:     TodoMarker,
		Icon:        o.Name + ".svg",
		Image:       api.AppImage{OS: "freebsd", ReleaseMin: "15.1"},
		Resources:   api.AppResources{Memory: "256M", Disk: "2G", CPU: "1"},
		Notes:       TodoMarker + ": what to do after the installation: the first-run steps, how to connect.\n",
	}
	todo["homepage"] = "the software's homepage"
	if o.Category != "" {
		if !slices.Contains(api.AppCategories, api.AppCategory(o.Category)) {
			return Draft{}, fmt.Errorf("unknown category %q (categories: %s)", o.Category, joinCategories())
		}
		a.Category = api.AppCategory(o.Category)
	} else {
		todo["category"] = "choose the category"
	}

	for _, p := range o.Packages {
		a.Packages = append(a.Packages, api.AppPackage{Name: p, Repo: "ports"})
	}
	if len(a.Packages) == 0 {
		a.Packages = []api.AppPackage{{Name: TodoMarker, Repo: "ports"}}
		todo["packages"] = "the package names, as 'pkg search' shows them"
	}
	t := true
	for _, s := range o.Services {
		a.Services = append(a.Services, api.AppService{Name: s, Start: &t})
	}
	if len(a.Services) == 0 {
		todo["services"] = "the rc.d scripts the packages install (ls /usr/local/etc/rc.d in a jail that has them); [] for none"
	}

	base := o.Name
	if len(o.Services) > 0 {
		base = o.Services[0]
	}
	if !api.IsName(base, 32) {
		base = "main"
	}
	for i, spec := range o.Ports {
		p, err := ParsePort(spec)
		if err != nil {
			return Draft{}, err
		}
		p.Name = base
		if i > 0 {
			p.Name = trimSlug(base, strconv.Itoa(p.Port))
		}
		a.Ports = append(a.Ports, p)
	}
	if len(a.Ports) == 0 {
		todo["ports"] = "the ports the services listen on (sockstat -l -4 -6 in the jail); [] for none"
	}

	a.Data = []api.AppPath{{Path: "/var/db/" + o.Name}}
	todo["data"] = "the directories that hold the state; [] for none"
	cfg := api.AppConfig{Path: "/usr/local/etc/" + o.Name + ".conf"}
	if len(a.Services) > 0 {
		cfg.Restart = a.Services[0].Name
	}
	a.Config = []api.AppConfig{cfg}
	todo["config"] = "the files a person edits, and the service each one restarts; [] for none"
	a.Logs = []api.AppLog{{Name: "server", Path: "/var/log/" + o.Name + ".log"}}
	todo["logs"] = "where the services log (many log to /var/log/messages through syslog); [] for none"
	a.Setup = [][]string{{"/usr/sbin/chown", TodoMarker + ":" + TodoMarker, "/var/db/" + o.Name}}

	for _, p := range a.Ports {
		if p.Proto == "tcp" {
			a.Health = &api.AppHealth{TCP: p.Port, WaitSeconds: 60}
			break
		}
	}
	if a.Health == nil {
		todo["health"] = "a check that the app answers (tcp, http or exec)"
	}

	d := Draft{App: a, Todo: todo}
	if _, err := Parse(o.Name, d.YAML()); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// ParsePort reads "N" or "N/proto" (tcp or udp; tcp when left out).
func ParsePort(s string) (api.AppPort, error) {
	num, proto, ok := strings.Cut(s, "/")
	if !ok {
		proto = "tcp"
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
		return api.AppPort{}, fmt.Errorf("port %q must be N or N/tcp or N/udp, with N from 1 to 65535", s)
	}
	return api.AppPort{Port: n, Proto: proto}, nil
}

// trimSlug joins a slug and a suffix with a dash within the 32 characters of a port or log name.
func trimSlug(base, suffix string) string {
	if len(base)+1+len(suffix) > 32 {
		base = strings.TrimRight(base[:32-1-len(suffix)], "-")
	}
	return base + "-" + suffix
}

// titleOf makes a title from an app name: dashes become spaces, the first letter upper case.
func titleOf(name string) string {
	t := strings.ReplaceAll(name, "-", " ")
	return strings.ToUpper(t[:1]) + t[1:]
}

// StarterIcon is a neutral placeholder icon: a rounded square with the first
// letter of the name, 24 by 24, a valid SVG document well within the bounds
// of an icon.
func StarterIcon(name string) []byte {
	letter := "?"
	if name != "" {
		letter = strings.ToUpper(name[:1])
	}
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">` +
		`<rect x="1" y="1" width="22" height="22" rx="5" fill="#5b6b7a"/>` +
		`<text x="12" y="16.5" font-family="sans-serif" font-size="13" font-weight="600" fill="#ffffff" text-anchor="middle">` + letter + `</text>` +
		"</svg>\n")
}
