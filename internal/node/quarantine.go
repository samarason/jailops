package node

import (
	"context"
	"errors"
	"time"

	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
)

// Corrupt chunks are quarantined, not merely reported: the blob is copied to
// quarantine/<id> and removed from chunks/, so from that moment it no longer
// answers "present" to a host's check, and the next backup that holds the same
// plaintext uploads a fresh healthy copy (the key is free again, and every
// upload is create-only). The bad blob is kept for inspection until the chunk
// is healthy again and PurgeQuarantine runs.

// QuarantinedChunk is an entry of the quarantine area.
type QuarantinedChunk struct {
	ID     string    `json:"id"`
	Size   int64     `json:"size"`
	Since  time.Time `json:"since"`
	Healed bool      `json:"healed"` // a healthy copy is in chunks/ again
}

// Quarantine moves a corrupt chunk out of the live chunk namespace. It is
// idempotent, and does nothing when the chunk is healthy, gone, or was healed
// by a concurrent upload in the meantime.
func (n *Node) Quarantine(ctx context.Context, id format.ID) (bool, error) {
	return n.quarantine(ctx, id, false)
}

// QuarantineChunk moves a chunk aside although it passes the keyless check: a host found that it does not
// decrypt or does not match its id. The node holds no key and cannot tell a chunk another host of the key
// domain uploaded with the wrong content from a good one; an administrator decides on a host's report. Once it
// is gone from chunks/, the next backup that holds the same plaintext uploads it again.
func (n *Node) QuarantineChunk(ctx context.Context, id format.ID, actor, remote string) (bool, error) {
	moved, err := n.quarantine(ctx, id, true)
	if err == nil {
		n.audit(ctx, actor, "quarantine.add", id.String(), map[string]any{"moved": moved}, remote)
	}
	return moved, err
}

func (n *Node) quarantine(ctx context.Context, id format.ID, force bool) (bool, error) {
	n.gcMu.RLock()
	defer n.gcMu.RUnlock()
	key := chunkKey(id)
	info, err := n.be.Head(ctx, key)
	if errors.Is(err, datastore.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var blob []byte
	if info.Size <= format.MaxBlobSize {
		// Re-check under the lock: a concurrent heal may have replaced it with a good blob.
		blob, err = datastore.ReadAll(ctx, n.be, key, format.MaxBlobSize)
		if errors.Is(err, datastore.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !force && format.VerifyBlob(blob) == nil {
			return false, nil
		}
	} // an object larger than any blob is corrupt by definition; only a marker is kept
	if err := datastore.PutBytes(ctx, n.be, quarantineKey(id), blob, datastore.PutOptions{}); err != nil {
		return false, err
	}
	if err := n.be.Delete(ctx, key); err != nil {
		return false, err
	}
	return true, nil
}

// ListQuarantine returns the quarantined chunks.
func (n *Node) ListQuarantine(ctx context.Context) ([]QuarantinedChunk, error) {
	var out []QuarantinedChunk
	err := n.be.List(ctx, quarDir, func(o datastore.ObjectInfo) error {
		name := o.Key[len(quarDir):]
		id, perr := format.ParseID(name)
		if perr != nil {
			return nil
		}
		out = append(out, QuarantinedChunk{ID: id.String(), Size: o.Size, Since: o.ModTime})
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		id, _ := format.ParseID(out[i].ID)
		out[i].Healed = n.chunkHealthy(ctx, id)
	}
	return out, nil
}

func (n *Node) chunkHealthy(ctx context.Context, id format.ID) bool {
	b, err := datastore.ReadAll(ctx, n.be, chunkKey(id), format.MaxBlobSize+1)
	return err == nil && format.VerifyBlob(b) == nil
}

// PurgeQuarantine deletes quarantined blobs whose chunk is healthy again and
// that were quarantined more than olderThan ago.
func (n *Node) PurgeQuarantine(ctx context.Context, olderThan time.Duration) (int, error) {
	q, err := n.ListQuarantine(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, c := range q {
		if c.Healed && n.now().Sub(c.Since) > olderThan {
			id, _ := format.ParseID(c.ID)
			if n.be.Delete(ctx, quarantineKey(id)) == nil {
				removed++
			}
		}
	}
	return removed, nil
}
