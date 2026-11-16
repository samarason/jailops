package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// fileJournal is a plan.Journal that keeps one JSON file per run, written
// through a temp file, fsync and rename. Next to each record it can hold the
// request that started the run (needed to rebuild the plan after a crash).
type fileJournal struct {
	dir string
	mu  sync.Mutex
}

func newFileJournal(dir string) (*fileJournal, error) {
	if dir == "" {
		return nil, errors.New("service: JournalDir is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("service: journal dir: %w", err)
	}
	return &fileJournal{dir: dir}, nil
}

// Run ids contain "/" ("upgrade/web"); jail, image and generation names never
// contain "~".
func encID(id string) string { return strings.ReplaceAll(id, "/", "~") }
func decID(s string) string  { return strings.ReplaceAll(s, "~", "/") }

func (j *fileJournal) path(id, ext string) string { return filepath.Join(j.dir, encID(id)+ext) }

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (j *fileJournal) Put(_ context.Context, r plan.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return writeFileAtomic(j.path(r.ID, ".json"), b)
}

func (j *fileJournal) Get(_ context.Context, id string) (plan.Record, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var r plan.Record
	b, err := os.ReadFile(j.path(id, ".json"))
	if errors.Is(err, os.ErrNotExist) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, false, fmt.Errorf("journal %s: %w", id, err)
	}
	return r, true, nil
}

func (j *fileJournal) Delete(_ context.Context, id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.Remove(j.path(id, ".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (j *fileJournal) List(_ context.Context) ([]plan.Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ents, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	var out []plan.Record
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(j.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r plan.Record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("journal %s: %w", e.Name(), err)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// opRequest is what must survive a crash to rebuild a plan: the inputs that
// the plan builders consume, including the stamp that names their snapshots.
type opRequest struct {
	OpID string `json:"op_id"`
	Kind string `json:"kind"`
	Jail string `json:"jail,omitempty"`
	// Stamp names the plan's snapshots.
	Stamp string `json:"stamp,omitempty"`
	// Spec is the full jail for create.
	Create *api.Jail `json:"create,omitempty"`
	// Upgrade is the request of an upgrade; State the switch state it recorded.
	Upgrade  *lifecycle.UpgradeRequest  `json:"upgrade,omitempty"`
	State    *lifecycle.SwitchState     `json:"state,omitempty"`
	Rollback *lifecycle.RollbackOptions `json:"rollback,omitempty"`
	Copy     *copyRequest               `json:"copy,omitempty"`
	// TargetGen is the generation a root rollback was switching to.
	TargetGen int `json:"target_gen,omitempty"`
	// Rename holds the steps of a rename.
	Rename *renameRequest `json:"rename,omitempty"`
	// Volume is the request of a volume's creation.
	Volume *lifecycle.VolumeRequest `json:"volume,omitempty"`
}

type copyRequest struct {
	Src, Dst, UUID string
}

func (j *fileJournal) putRequest(id string, r opRequest) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return writeFileAtomic(j.path(id, ".req"), b)
}

func (j *fileJournal) getRequest(id string) (opRequest, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var r opRequest
	b, err := os.ReadFile(j.path(id, ".req"))
	if err != nil {
		return r, false
	}
	if json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

func (j *fileJournal) deleteRequest(id string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = os.Remove(j.path(id, ".req"))
}

// strayRequests lists request files without a journal record.
func (j *fileJournal) requestIDs() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ents, _ := os.ReadDir(j.dir)
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".req") {
			out = append(out, decID(strings.TrimSuffix(e.Name(), ".req")))
		}
	}
	return out
}
