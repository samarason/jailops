package format

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ManifestFormat is the version of the manifest JSON.
const ManifestFormat = 1

// MaxManifestSize bounds a manifest blob.
const MaxManifestSize = 16 << 20

// StreamKind values.
const (
	// StreamFiles is a directory tree: payload (file bytes) followed by a catalog.
	StreamFiles = "files"
)

// Manifest is the encrypted description of one backup snapshot of a jail. The
// node stores it opaquely; only a host holding the key can read it.
type Manifest struct {
	Format     int       `json:"format"`
	SnapshotID string    `json:"snapshot_id"`
	PreviousID string    `json:"previous_id,omitempty"` // informational: snapshots are self-contained
	Created    time.Time `json:"created"`
	// Host and Jail are identities (uuids); JailName is the display name at
	// the time of the backup.
	Host     string `json:"host"`
	Jail     string `json:"jail"`
	JailName string `json:"jail_name,omitempty"`
	Policy   string `json:"policy,omitempty"`
	// IndexDigest is the SHA-256 of the whole index file.
	IndexDigest string `json:"index_digest"`
	// Streams lists the datasets of the jail. They occupy consecutive ranges
	// of the one index, in this order.
	Streams []Stream `json:"streams"`
	// Bundle is the restore closure (jail spec, networks, policies, secret
	// references). It is opaque to this package.
	Bundle json.RawMessage   `json:"bundle,omitempty"`
	Meta   map[string]string `json:"meta,omitempty"`
	Stats  Stats             `json:"stats"`
}

// Stream is one dataset's range of the index.
type Stream struct {
	Name string `json:"name"` // dataset name
	Kind string `json:"kind"` // StreamFiles
	// Offset is where the stream starts in the index (a chunk boundary);
	// the payload occupies [Offset, Offset+PayloadSize) and the catalog the
	// CatalogSize bytes after it.
	Offset      uint64 `json:"offset"`
	PayloadSize uint64 `json:"payload_size"`
	CatalogSize uint64 `json:"catalog_size"`
	Entries     int    `json:"entries"`
	// Mode is "full" when every file was read, "incremental" when unchanged
	// runs were reused from Base.
	Mode       string    `json:"mode"`
	Base       string    `json:"base,omitempty"`
	LastFull   time.Time `json:"last_full"`
	TrustCtime bool      `json:"trust_ctime"`
	// ZFS identity of the consistent snapshot that was read.
	ZFSSnapshot string            `json:"zfs_snapshot,omitempty"`
	GUID        uint64            `json:"guid,omitempty"`
	CreateTxg   uint64            `json:"createtxg,omitempty"`
	Props       map[string]string `json:"props,omitempty"`
	Stats       Stats             `json:"stats"`
}

// Stats records what a backup run did.
type Stats struct {
	LogicalBytes  uint64 `json:"logical_bytes"`
	ReadBytes     uint64 `json:"read_bytes"`
	ReusedBytes   uint64 `json:"reused_bytes"`
	UploadedBytes uint64 `json:"uploaded_bytes"`
	NewChunks     int    `json:"new_chunks"`
	Files         int64  `json:"files"`
	FullRead      bool   `json:"full_read"`
	DurationMs    int64  `json:"duration_ms"`
}

func manifestAAD(group, snapshot string) []byte {
	aad := []byte(manifestMagic)
	aad = append(aad, manifestVersion, 0, 0, 0)
	aad = append(aad, group...)
	aad = append(aad, 0)
	aad = append(aad, snapshot...)
	return aad
}

const (
	manifestMagic   = "JOMF"
	manifestVersion = 1
)

// SealManifest encrypts the manifest for the given group. nonce may be nil.
func (k *Keys) SealManifest(m *Manifest, group string, nonce []byte) ([]byte, error) {
	c := *m
	c.Format = ManifestFormat
	pt, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	} else if len(nonce) != NonceSize {
		return nil, errors.New("bad nonce size")
	}
	aead, err := chacha20poly1305.NewX(k.Manifest[:])
	if err != nil {
		return nil, err
	}
	out := []byte(manifestMagic)
	out = append(out, manifestVersion, 0, 0, 0)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, pt, manifestAAD(group, m.SnapshotID))
	return appendTrailer(out), nil
}

// VerifyManifestBlob checks structure and the SHA-256 trailer without a key.
func VerifyManifestBlob(blob []byte) error {
	if len(blob) > MaxManifestSize {
		return errors.New("manifest: too large")
	}
	body, err := checkTrailer(blob)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	if len(body) < 8+NonceSize+chacha20poly1305.Overhead || string(body[:4]) != manifestMagic {
		return errors.New("manifest: bad magic or length")
	}
	if body[4] != manifestVersion || body[5] != 0 || body[6] != 0 || body[7] != 0 {
		return errors.New("manifest: unsupported version or reserved bytes")
	}
	return nil
}

// OpenManifest decrypts and parses a manifest blob stored for (group, snapshot).
func (k *Keys) OpenManifest(blob []byte, group, snapshot string) (*Manifest, error) {
	if err := VerifyManifestBlob(blob); err != nil {
		return nil, err
	}
	body := blob[:len(blob)-trailerSize]
	nonce := body[8 : 8+NonceSize]
	ct := body[8+NonceSize:]
	aead, err := chacha20poly1305.NewX(k.Manifest[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, manifestAAD(group, snapshot))
	if err != nil {
		return nil, errors.New("manifest authentication failed (wrong key, group, snapshot or corruption)")
	}
	m := &Manifest{}
	if err := json.Unmarshal(pt, m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format != ManifestFormat || m.SnapshotID != snapshot {
		return nil, errors.New("manifest: content does not match its location")
	}
	return m, nil
}

// CheckIndex verifies that file is the index this manifest describes and that
// the streams tile it exactly.
func (m *Manifest) CheckIndex(file []byte, idx *Index) error {
	if m.IndexDigest != FileDigest(file) {
		return errors.New("the index does not match its manifest: the repository was modified")
	}
	var pos uint64
	for i, s := range m.Streams {
		if s.Offset != pos {
			return fmt.Errorf("stream %d starts at %d, expected %d", i, s.Offset, pos)
		}
		if s.PayloadSize > idx.Size || s.CatalogSize > idx.Size || pos+s.PayloadSize+s.CatalogSize > idx.Size {
			return fmt.Errorf("stream %d lies outside the index", i)
		}
		pos += s.PayloadSize + s.CatalogSize
	}
	if pos != idx.Size {
		return fmt.Errorf("streams cover %d bytes, the index holds %d", pos, idx.Size)
	}
	return nil
}

// ---- snapshot ids -------------------------------------------------------------

// NewSnapshotID returns a sortable id: YYYYMMDDHHMMSS-xxxxxxxx (UTC). It only
// uses [0-9a-f-], so it is safe in object keys and file names.
//
// With r == nil the suffix is the microsecond within the second (20 bits) followed by
// 12 random bits, so ids created in the same second still sort in creation order and
// two created in the same microsecond (a frozen clock in a test) differ in 4095 of 4096 cases.
// With an explicit reader (tests) the suffix is 4 bytes read from it.
func NewSnapshotID(t time.Time, r io.Reader) (string, error) {
	t = t.UTC()
	var b [4]byte
	if r == nil {
		var rb [2]byte
		if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
			return "", err
		}
		v := uint32(t.Nanosecond()/1000)<<12 | (uint32(rb[0])<<8|uint32(rb[1]))&0xfff
		b = [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	} else if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return t.Format("20060102150405") + "-" + hex.EncodeToString(b[:]), nil
}

// SnapshotIDTime returns the (UTC, whole-second) time a snapshot id was created at.
func SnapshotIDTime(s string) (time.Time, error) {
	if !ValidSnapshotID(s) {
		return time.Time{}, fmt.Errorf("invalid snapshot id %q", s)
	}
	t, err := time.ParseInLocation("20060102150405", s[:14], time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid snapshot id %q: %w", s, err)
	}
	return t, nil
}

// ValidSnapshotID reports whether s looks like an id from NewSnapshotID.
func ValidSnapshotID(s string) bool {
	if len(s) != 14+1+8 || s[14] != '-' {
		return false
	}
	for i, c := range []byte(s) {
		if i == 14 {
			continue
		}
		if !(c >= '0' && c <= '9') && !(i > 14 && c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidGroupID reports whether g is a well-formed group id (32 lowercase hex).
func ValidGroupID(g string) bool {
	if len(g) != 32 {
		return false
	}
	for _, c := range []byte(g) {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
