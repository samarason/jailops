package cli

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

// applier creates or updates one document of a kind.
type applier func(ctx context.Context, doc map[string]any) error

// appliers maps every kind 'apply' handles to its descriptor.
func (a *app) appliers() map[api.Kind]applier {
	return map[api.Kind]applier{
		api.KindJail:           applyWith(a, a.jailDesc()),
		api.KindVolume:         applyWith(a, volumeDesc()),
		api.KindImage:          applyWith(a, imageDesc()),
		api.KindNetwork:        applyWith(a, networkDesc()),
		api.KindProject:        applyWith(a, a.projectDesc()),
		api.KindStorage:        applyWith(a, storageDesc()),
		api.KindWireGuard:      applyWith(a, wireguardDesc()),
		api.KindFirewallPolicy: applyWith(a, policyDesc()),
		api.KindAddressSet:     applyWith(a, addrSetDesc()),
		api.KindBackupTarget:   applyWith(a, targetDesc()),
		api.KindBackupPolicy:   applyWith(a, backupPolicyDesc()),
		api.KindProfile:        applyWith(a, profileDesc()),
		api.KindRemote:         applyWith(a, hostDesc()),
	}
}

// projectKinds are the kinds that live in a project.
var projectKinds = map[api.Kind]bool{api.KindJail: true, api.KindVolume: true, api.KindFirewallPolicy: true, api.KindAddressSet: true, api.KindBackupPolicy: true, api.KindProfile: true}

// applyWith is the applier of one kind: create the object when it is new,
// update it when the document differs, leave it alone otherwise.
func applyWith[T any](a *app, d *kindDesc[T]) applier {
	return func(ctx context.Context, doc map[string]any) error {
		x, err := d.parse(api.ObjectMeta{}, doc, "")
		if err != nil {
			return err
		}
		name := d.name(x)
		c, err := a.connect(ctx)
		if err != nil {
			return err
		}
		cur, etag, err := d.get(ctx, c, name)
		if err != nil {
			if !api.IsCode(err, api.CodeNotFound) {
				return err
			}
			if ok, err := a.dry("create "+d.noun+" "+name, document(d.kind, *d.meta(&x), d.specOf(&x))); ok || err != nil {
				return err
			}
			h, out, err := d.create(ctx, c, x)
			if err != nil {
				return err
			}
			if err := a.finishOp(ctx, h, d.noun, name, "created", out); err != nil {
				return err
			}
			createWarnings(a, d, out)
			return nil
		}
		next := cur
		d.setSpec(&next, x)
		before, _ := json.Marshal(document(d.kind, *d.meta(&cur), d.specOf(&cur)))
		after, _ := json.Marshal(document(d.kind, *d.meta(&next), d.specOf(&next)))
		if string(before) == string(after) {
			a.say("%s/%s unchanged\n", d.noun, name)
			return nil
		}
		if ok, err := a.dry("update "+d.noun+" "+name, document(d.kind, *d.meta(&next), d.specOf(&next))); ok || err != nil {
			return err
		}
		out, err := d.update(ctx, c, name, next, etag)
		if err != nil {
			return err
		}
		if err := a.finishOp(ctx, nil, d.noun, name, "updated", out); err != nil {
			return err
		}
		if d.updated != nil {
			d.updated(a, out)
		}
		return nil
	}
}

// applyCmd is 'jailops apply -f FILE'.
func (a *app) applyCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "apply -f FILE",
		Short: "Create or update objects from a file",
		Long: `Create or update the objects of a YAML or JSON file ("-" reads standard input),
document by document, in order. Every document uses the declarative envelope
(apiVersion, kind, metadata, spec). An object that does not exist is created;
one that exists is replaced by the document, with the ETag of the version that
was read so a concurrent change is detected; one that already matches is left
alone. The file is checked as a whole first (kinds, project); a document the
server refuses stops the command, and the ones before it stay applied.

Kinds: Jail, Image, Network, Project, Storage, FirewallPolicy, AddressSet,
BackupTarget, BackupPolicy, Profile and Remote. Jails, firewall policies,
address sets, backup policies and profiles need a project (--project,
JAILOPS_PROJECT or 'project switch'). With --dry-run every document is read and
checked and what would be sent is printed; nothing is sent.`,
		Example: `jailops apply -f site.yaml
jailops apply -f site.yaml --dry-run
cat jails.yaml | jailops apply -f - --project web`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return usagef("-f FILE is required")
			}
			b, err := a.readInput(file)
			if err != nil {
				return err
			}
			docs, err := readDocs(b)
			if err != nil {
				return err
			}
			conn, err := a.resolveConnection()
			if err != nil {
				return err
			}
			appliers := a.appliers()
			kinds := make([]api.Kind, len(docs))
			for i, doc := range docs { // every document must be one we can apply before any is sent
				kind, _ := doc["kind"].(string)
				if kind == "" {
					return usagef("document %d has no kind: apply needs the envelope (apiVersion, kind, metadata, spec)", i+1)
				}
				if appliers[api.Kind(kind)] == nil {
					return usagef("document %d: apply does not handle kind %q", i+1, kind)
				}
				if projectKinds[api.Kind(kind)] && conn.Project == "" {
					return a.requireProject()
				}
				kinds[i] = api.Kind(kind)
			}
			for i, doc := range docs {
				kind := kinds[i]
				if err := appliers[kind](cmd.Context(), doc); err != nil {
					var ue *usageError
					if errors.As(err, &ue) { // a mistake in the file: say which document
						return usagef("document %d (%s): %v", i+1, kind, ue.err)
					}
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML or JSON file with one or more documents, or - for standard input")
	return cmd
}
