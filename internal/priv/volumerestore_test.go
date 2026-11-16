package priv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jailops.net/jailops/internal/sys/zfs"
)

// volumeAt makes a volume dataset the way ZFS reports a mounted one, behind the helper's back (a finished volume).
func volumeAt(t *testing.T, e *env, ctx context.Context, project, name, complete string) (ds, mp string) {
	t.Helper()
	ds = "tank/jailops/projects/" + project + "/volumes/" + name
	mp = filepath.Join(e.cfg.MountBase, "projects", project, "volumes", name)
	if err := os.MkdirAll(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.zfs.Create(ctx, zfs.CreateOpts{Name: ds, Parents: true,
		Props: map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "jailops:complete": complete, "mountpoint": mp, "mounted": "yes"}}); err != nil {
		t.Fatal(err)
	}
	return ds, mp
}

// Only a volume the restore itself created, incomplete, is written through an agent, and only until it is complete:
// a finished volume or jail never is, nor is another project's volume, nor is one whose properties the daemon set.
func TestAgentWritesOnlyTheVolumeAnActiveRestoreCreated(t *testing.T) {
	e, ctx := agentEnv(t)
	g := e.local.ZFS()
	jailMP := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")

	// finished ones: a volume of the same project, a volume of another project, a finished jail
	_, finished := volumeAt(t, e, ctx, "web", "mail", "on")
	_, foreign := volumeAt(t, e, ctx, "other", "mail", "on")
	// the daemon sets any user property on its own datasets: incomplete by property is not incomplete by creation
	dsFake, faked := volumeAt(t, e, ctx, "web", "faked", "on")
	if err := e.zfs.Set(ctx, dsFake, map[string]string{"jailops:complete": "off"}); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{"a finished volume": finished, "another project's volume": foreign, "a volume set incomplete": faked, "a finished jail": jailMP} {
		if _, err := e.local.checkAgentRoot(ctx, AgentWrite, root); err == nil {
			t.Errorf("%s was writable through an agent", name)
		}
	}

	// the restore creates its volume incomplete through the helper: writable until it is complete
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "volumes", "mail2")
	ds := "tank/jailops/projects/web/volumes/mail2"
	if err := os.MkdirAll(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := g.Create(ctx, zfs.CreateOpts{Name: ds, Parents: true, Props: map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "jailops:complete": "off", "mountpoint": mp}}); err != nil {
		t.Fatal(err)
	}
	_ = e.zfs.Set(ctx, ds, map[string]string{"mounted": "yes"})
	got, err := e.local.checkAgentRoot(ctx, AgentWrite, mp)
	if err != nil || got != ds {
		t.Fatalf("the volume of an active restore: %q, %v", got, err)
	}
	// it opens no other dataset
	for name, root := range map[string]string{"the finished volume next to it": finished, "another project's": foreign, "the jail": jailMP} {
		if _, err := e.local.checkAgentRoot(ctx, AgentWrite, root); err == nil {
			t.Errorf("a restore of one volume opened %s", name)
		}
	}
	// complete: closed again
	if err := g.Set(ctx, ds, map[string]string{"jailops:complete": "on"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentWrite, mp); err == nil {
		t.Fatal("a volume marked complete was still writable")
	}
}

// An encrypted volume made for a restore is writable the same way, through the helper's key operation.
func TestAgentWritesTheEncryptedVolumeAnActiveRestoreCreated(t *testing.T) {
	f, _ := newKeyFixture(t, "available")
	ctx := WithAdmin(context.Background(), "alice")
	ds := vkVolumes + "/restored"
	mp := filepath.Join(f.cfg.MountBase, "projects", "alpha", "volumes", "restored")
	if err := os.MkdirAll(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	props := map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "jailops:complete": "off", "mountpoint": mp}
	if err := f.client.CreateEncrypted(context.Background(), zfs.CreateOpts{Name: ds, Props: props}, []byte(vkPass)); err != nil {
		t.Fatal(err)
	}
	_ = f.zfs.Set(ctx, ds, map[string]string{"mountpoint": mp, "mounted": "yes"})
	if got, err := f.local.checkAgentRoot(ctx, AgentWrite, mp); err != nil || got != ds {
		t.Fatalf("the encrypted volume of an active restore: %q, %v", got, err)
	}
	if err := f.local.ZFS().Set(ctx, ds, map[string]string{"jailops:complete": "on"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.checkAgentRoot(ctx, AgentWrite, mp); err == nil {
		t.Fatal("an encrypted volume marked complete was still writable")
	}
	// a finished encrypted volume is not
	if _, err := f.local.checkAgentRoot(ctx, AgentWrite, filepath.Join(f.cfg.MountBase, "projects", "alpha", "volumes", "db")); err == nil {
		t.Fatal("a finished encrypted volume was writable")
	}
}
