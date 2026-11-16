package validate

import (
	"fmt"
	"regexp"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// MaxJailKeyLen is the longest qualified jail name (the OS-level jail name).
const MaxJailKeyLen = 64

var jailKeyRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(_[a-z][a-z0-9-]*)?$`)

// ProjectName validates a project name: the Name rule, and the names the API
// reserves for itself are refused.
func ProjectName(name string) error {
	if err := Name("name", name); err != nil {
		return err
	}
	switch name {
	case "all", "host":
		return Invalid("name", "project name %q is reserved", name)
	}
	return nil
}

// QualifiedName returns the project-qualified internal name of a jail: project_name. There is no default project, so
// the project is always part of the key. Underscore is not allowed in either part, so two different (project, name)
// pairs never give the same key, and the key is a valid OS jail name and dataset component.
func QualifiedName(project, name string) (string, error) {
	if err := Name("name", name); err != nil {
		return "", err
	}
	if project == "" {
		return "", Invalid("project", "a project is required")
	}
	if err := Name("project", project); err != nil {
		return "", err
	}
	k := project + "_" + name
	if len(k) > MaxJailKeyLen {
		return "", Invalid("name", "project %q and jail %q are too long together", project, name).
			WithHint(fmt.Sprintf("the project and jail names together may be at most %d characters (the jail key project_jail at most %d)", MaxJailKeyLen-1, MaxJailKeyLen))
	}
	return k, nil
}

// SplitQualified inverts QualifiedName. A key without a project part returns an empty project.
func SplitQualified(key string) (project, name string) {
	if p, n, ok := strings.Cut(key, "_"); ok {
		return p, n
	}
	return "", key
}

// JailKey accepts exactly the keys QualifiedName produces.
func JailKey(field, key string) error {
	if len(key) > MaxJailKeyLen || !jailKeyRE.MatchString(key) {
		return Invalid(field, "%s %q is not a valid jail name", field, key)
	}
	if !strings.Contains(key, "_") {
		return Invalid(field, "%s %q is not canonical: a jail name carries its project (project_name)", field, key)
	}
	for _, part := range strings.Split(key, "_") {
		if len(part) > 63 {
			return Invalid(field, "%s %q has a part longer than 63 characters", field, key)
		}
	}
	return nil
}

func starOr(field, v string) error {
	if v == "*" {
		return nil
	}
	return Name(field, v)
}

// ProjectSpec validates the shape of a project. Whether the named networks,
// storage and policy exist is for the service to check.
func ProjectSpec(name string, s api.ProjectSpec) error {
	if err := ProjectName(name); err != nil {
		return err
	}
	if err := api.ValidFreeText("comment", s.Comment, false); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, n := range s.Networks {
		f := fmt.Sprintf("networks[%d]", i)
		// a network belongs to one project, so there is no wildcard grant of every network
		if err := Name(f+".network", n.Network); err != nil {
			return err
		}
		if seen[n.Network] {
			return Invalid(f+".network", "network %q is granted twice", n.Network)
		}
		seen[n.Network] = true
	}
	seen = map[string]bool{}
	for i, st := range s.Storage {
		f := fmt.Sprintf("storage[%d]", i)
		if err := starOr(f+".storage", st.Storage); err != nil {
			return err
		}
		if seen[st.Storage] {
			return Invalid(f+".storage", "storage %q is granted twice", st.Storage)
		}
		seen[st.Storage] = true
		if st.Quota != "" {
			if _, err := ParseSize(st.Quota); err != nil {
				return Invalid(f+".quota", "quota %q is not a size", st.Quota)
			}
		}
	}
	q := s.Quotas
	for f, v := range map[string]int{"quotas.jails": q.Jails, "quotas.cpu": q.CPU, "quotas.pids": q.PIDs, "quotas.addresses": q.Addresses} {
		if v < 0 {
			return Invalid(f, "%s must not be negative", f)
		}
	}
	if q.Memory != "" {
		if _, err := ParseSize(q.Memory); err != nil {
			return Invalid("quotas.memory", "memory %q is not a size", q.Memory)
		}
	}
	if err := PolicyNames("firewall_policies", s.FirewallPolicies); err != nil {
		return err
	}
	seen = map[string]bool{}
	for i, im := range s.Images {
		if !api.IsName(im, api.MaxName) {
			return Invalid(fmt.Sprintf("images[%d]", i), "image name %q is invalid", im)
		}
		if seen[im] {
			return Invalid(fmt.Sprintf("images[%d]", i), "image %q is listed twice", im)
		}
		seen[im] = true
	}
	seen = map[string]bool{}
	for i, h := range s.Hosts {
		f := fmt.Sprintf("hosts[%d]", i)
		if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t\r\n/\\") {
			return Invalid(f, "host %q is invalid", h)
		}
		if seen[h] {
			return Invalid(f, "host %q is listed twice", h)
		}
		seen[h] = true
	}
	return nil
}

var (
	datasetCompRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
	compressionRE = regexp.MustCompile(`^(off|on|lz4|zle|zstd|zstd-([1-9]|1[0-9])|gzip|gzip-[1-9])$`)
)

// StorageSpec validates the shape of a storage.
func StorageSpec(name string, s api.StorageSpec) error {
	if err := Name("name", name); err != nil {
		return err
	}
	if err := api.ValidFreeText("comment", s.Comment, false); err != nil {
		return err
	}
	d := s.Dataset
	if d == "" || len(d) > 200 || strings.HasPrefix(d, "/") || !strings.Contains(d, "/") {
		return Invalid("dataset", "dataset %q must look like pool/name", d)
	}
	for _, c := range strings.Split(d, "/") {
		if c == "" || !datasetCompRE.MatchString(c) {
			return Invalid("dataset", "dataset %q has an invalid component %q", d, c)
		}
	}
	if s.Compression != "" && !compressionRE.MatchString(s.Compression) {
		return Invalid("compression", "compression %q is not supported", s.Compression)
	}
	return nil
}
