package api

// Rename is the body of POST /api/v1/<kind>/{name}/rename (extension "rename"): it gives an object a new name and
// rewrites every reference to it in one operation, or changes nothing. The If-Match header of the request is checked
// against the object's generation.
type Rename struct {
	// NewName follows the name rule of the kind's create.
	NewName string `json:"new_name"`
	// DryRun answers the plan (RenameResult with dry_run) at once and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// What a rename change touches (RenameChange.Kind).
const (
	RenameObject    = "object"    // the renamed object itself
	RenameReference = "reference" // a reference in another object (a jail spec, a project, a policy, ...)
	RenameDataset   = "dataset"   // a ZFS dataset renamed, or its mountpoint moved
	RenameAnchor    = "anchor"    // a PF anchor loaded under the new name
	RenameInterface = "interface" // an interface description rewritten
	RenameFile      = "file"      // a file of the daemon moved to the new name
	RenameState     = "state"     // a record of the daemon (update history, upgrade runs) moved
)

// RenameChange is one thing a rename changes.
type RenameChange struct {
	// Kind is object, reference, dataset, anchor, interface, file or state.
	Kind string `json:"kind"`
	// Object names what changes: "jail web (project alpha)", "dataset tank/jailops/projects/alpha", ...
	Object string `json:"object"`
	// Detail says how: "spec.network[0].network: lan -> office".
	Detail string `json:"detail,omitempty"`
}

// RenameResult is what a rename did (the operation's metadata) or would do (a dry run).
type RenameResult struct {
	Kind    Kind   `json:"kind"`
	Project string `json:"project,omitempty"`
	From    string `json:"from"`
	To      string `json:"to"`
	DryRun  bool   `json:"dry_run,omitempty"`
	// Changes lists every change, the object first.
	Changes []RenameChange `json:"changes"`
	// Counts are the changes by kind, for a one-line summary.
	Counts map[string]int `json:"counts"`
	// Steps are the steps of the operation in order, as a dry run of a plan lists them.
	Steps []string `json:"steps,omitempty"`
	// Warnings are what the rename does not change and the caller should know: a selector in jailopsd.yaml that
	// names the old name, connections a firewall change cuts, a hostname that follows the name.
	Warnings []string `json:"warnings,omitempty"`
}
