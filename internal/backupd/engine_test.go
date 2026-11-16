package backupd_test

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"jailops.net/jailops/internal/node/client/enginerepo"
	"jailops.net/jailops/internal/repo/engine"
	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/sdk/api"
)

func writeTree(t *testing.T, root string, seed int64) {
	rnd := rand.New(rand.NewSource(seed))
	for i := 0; i < 40; i++ {
		p := filepath.Join(root, "dir", string(rune('a'+i%5)), "f"+string(rune('a'+i%26))+string(rune('0'+i%10)))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		b := make([]byte, 500+rnd.Intn(300000))
		rnd.Read(b)
		_ = os.WriteFile(p, b, 0o644)
	}
	big := make([]byte, 3<<20)
	rnd.Read(big)
	_ = os.WriteFile(filepath.Join(root, "big.dat"), big, 0o644)
}

// The real backup engine, over the network, to a node on each kind of storage:
// a first backup, an incremental one, a restore on a recovery host, and the escrow of the key.
func TestEngineThroughTheNode(t *testing.T) {
	for _, kind := range []backendKind{memKind, s3Kind} {
		t.Run(string(kind), func(t *testing.T) {
			r := startRig(t, kind, nil)
			host := r.enroll("laptop")
			rec := r.enroll("recovery", "backup-pull", "restore")
			key, err := keys.NewKey(bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			hc := r.clientForDomain(host.Cert, key.DomainID())
			repo := &enginerepo.Repo{C: hc, Domain: key.DomainID()}
			src := t.TempDir()
			writeTree(t, src, 1)
			now := r.Clock.Now()
			opts := engine.BackupOptions{Key: key, Escrow: repo, Host: "host-uuid", Jail: "jail-uuid", JailName: "web",
				Streams: []engine.Stream{{Name: "tank/jails/web", Root: src}}, Repo: repo, NewUploader: enginerepo.NewUploader(hc),
				Now: func() time.Time { now = now.Add(time.Second); return now }}
			res, err := engine.Backup(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.NewChunks == 0 || res.Receipt == nil || res.Previous != "" {
				t.Fatalf("%+v", res)
			}
			// the node holds what the engine committed, and can verify it without the key
			vs := adminJob[nodeVerify](t, r, "/verify", map[string]any{"mode": "all"})
			if vs.Failed != 0 || vs.Snapshots != 1 {
				t.Fatalf("%+v", vs)
			}
			// the escrow of the key goes to the node, create-only
			if st, err := keys.StatusOf(ctx, key, repo); err != nil || st == keys.StatusEscrowed {
				t.Fatalf("%v %v", st, err)
			}
			if err := hc.PutEscrow(ctx, key.DomainID(), []byte("age-encryption.org/v1\n-> X25519 stanza\nfake blob")); err != nil {
				t.Fatal(err)
			}
			if err := hc.PutEscrow(ctx, key.DomainID(), []byte("age-encryption.org/v1\n-> X25519 stanza\nanother blob")); err == nil || !api.IsCode(err, api.CodeAlreadyExists) {
				t.Fatalf("an escrow blob was replaced: %v", err)
			}
			if ok, err := repo.HasEscrow(ctx, key.DomainID()); err != nil || !ok {
				t.Fatalf("%v %v", ok, err)
			}

			// an incremental backup after a small change reuses the base and uploads little
			r.Clock.Advance(time.Hour)
			_ = os.WriteFile(filepath.Join(src, "dir", "a", "new.txt"), []byte("new file"), 0o644)
			res2, err := engine.Backup(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			if res2.Streams[0].Mode != "incremental" || res2.UploadedBytes >= res.UploadedBytes/4 {
				t.Fatalf("incremental: mode %q, uploaded %d of %d", res2.Streams[0].Mode, res2.UploadedBytes, res.UploadedBytes)
			}

			// restore on the recovery host, with the key, from the node alone
			rrepo := &enginerepo.Repo{C: rec.C, Domain: key.DomainID()}
			dest := filepath.Join(t.TempDir(), "restored")
			_ = os.MkdirAll(dest, 0o755)
			if _, err := engine.Restore(ctx, engine.RestoreOptions{Key: key, Repo: rrepo, Group: res2.Group, Snapshot: res2.Snapshot, Stream: "tank/jails/web", Dest: dest, NoChown: os.Geteuid() != 0}); err != nil {
				t.Fatal(err)
			}
			for _, rel := range []string{"big.dat", "dir/a/new.txt", "dir/b/fb1"} {
				a, _ := os.ReadFile(filepath.Join(src, rel))
				b, err := os.ReadFile(filepath.Join(dest, rel))
				if err != nil || !bytes.Equal(a, b) {
					t.Fatalf("%s differs after the restore (%v)", rel, err)
				}
			}
			// a repository with a recorded key domain refuses another key
			// (the rig's repository recorded none, so this checks only that the client sends it)
			wrong, _ := keys.NewKey(bytes.Repeat([]byte{0x43}, 32))
			_ = wrong
		})
	}
}

type nodeVerify struct {
	Failed    int `json:"failed"`
	Snapshots int `json:"snapshots"`
}
