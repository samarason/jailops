package sdk

import (
	"context"
	"iter"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"jailops.net/jailops/sdk/api"
)

// ListOption filters a list request.
type ListOption func(url.Values)

// Label selects objects carrying the label (repeatable, all must match).
func Label(key, value string) ListOption {
	return func(q url.Values) { q.Add("label", key+"="+value) }
}

// Recursion sets ?recursion=. The server always returns full objects; the
// value is reserved for future use.
func Recursion(n int) ListOption { return func(q url.Values) { q.Set("recursion", strconv.Itoa(n)) } }

func list[T any](ctx context.Context, c *Client, path string, opts []ListOption) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		q := url.Values{}
		for _, o := range opts {
			o(q)
		}
		items, _, err := get[[]T](ctx, c, path, q)
		if err != nil {
			var zero T
			yield(zero, err)
			return
		}
		for _, it := range items {
			if !yield(it, nil) {
				return
			}
		}
	}
}

// Resource is the generic client of a plain /api/v1/<resource> collection.
type Resource[T any] struct {
	c    *Client
	path string
}

func newResource[T any](c *Client, path string) *Resource[T] { return &Resource[T]{c, path} }

func (r *Resource[T]) item(name string) string { return r.path + "/" + esc(name) }

// List iterates all objects, optionally filtered.
func (r *Resource[T]) List(ctx context.Context, opts ...ListOption) iter.Seq2[T, error] {
	return list[T](ctx, r.c, r.path, opts)
}

// Get fetches one object.
func (r *Resource[T]) Get(ctx context.Context, name string) (T, error) {
	v, _, err := r.GetETag(ctx, name)
	return v, err
}

// GetETag fetches one object and its ETag for use with Update.
func (r *Resource[T]) GetETag(ctx context.Context, name string) (T, string, error) {
	v, h, err := get[T](ctx, r.c, r.item(name), nil)
	return v, etagOf(h), err
}

// Create creates an object, waiting if the server answers asynchronously.
func (r *Resource[T]) Create(ctx context.Context, v T) (T, error) {
	out, _, err := send[T](ctx, r.c, request{method: http.MethodPost, path: r.path, body: v})
	return out, err
}

// Update replaces the object. A non-empty etag is sent as If-Match and a
// stale one fails with api.CodeConflict.
func (r *Resource[T]) Update(ctx context.Context, name string, v T, etag string) (T, error) {
	return updateAt[T](ctx, r.c, http.MethodPut, r.item(name), v, etag)
}

// Patch merges a JSON merge patch (RFC 7386) into the object.
func (r *Resource[T]) Patch(ctx context.Context, name string, patch any, etag string) (T, error) {
	return updateAt[T](ctx, r.c, http.MethodPatch, r.item(name), patch, etag)
}

// Delete removes the object, waiting if the server answers asynchronously.
func (r *Resource[T]) Delete(ctx context.Context, name string) error {
	_, _, err := send[None](ctx, r.c, request{method: http.MethodDelete, path: r.item(name)})
	return err
}

func updateAt[T any](ctx context.Context, c *Client, method, path string, body any, etag string) (T, error) {
	h := http.Header{}
	if etag != "" {
		h.Set("If-Match", quoteETag(etag))
	}
	out, _, err := send[T](ctx, c, request{method: method, path: path, body: body, header: h})
	return out, err
}

// Modifiable is a client that Modify can drive.
type Modifiable[T any] interface {
	GetETag(ctx context.Context, name string) (T, string, error)
	Update(ctx context.Context, name string, v T, etag string) (T, error)
}

// ModifyOption tunes Modify.
type ModifyOption func(*modifyCfg)

type modifyCfg struct{ retries int }

// MaxConflictRetries sets how many times Modify re-reads and re-applies after
// a conflict (default 5).
func MaxConflictRetries(n int) ModifyOption { return func(m *modifyCfg) { m.retries = n } }

// Modify reads an object with its ETag, applies fn and writes it back with
// If-Match. On a conflict (HTTP 412) it re-reads and applies fn again, so fn
// must be safe to run more than once.
func Modify[T any](ctx context.Context, r Modifiable[T], name string, fn func(*T), opts ...ModifyOption) error {
	cfg := modifyCfg{retries: 5}
	for _, o := range opts {
		o(&cfg)
	}
	for i := 0; ; i++ {
		v, etag, err := r.GetETag(ctx, name)
		if err != nil {
			return err
		}
		fn(&v)
		_, err = r.Update(ctx, name, v, etag)
		if err == nil {
			return nil
		}
		if !api.IsCode(err, api.CodeConflict) || i >= cfg.retries {
			return err
		}
		d := time.Duration(i+1) * (5*time.Millisecond + rand.N(20*time.Millisecond))
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Rename gives an object a new name and rewrites everything that refers to it, in one operation or not at all
// (extension "rename"). A non-empty etag is sent as If-Match. With req.DryRun the server answers at once with the
// plan and changes nothing; otherwise Wait returns what was changed.
func (r *Resource[T]) Rename(ctx context.Context, name string, req api.Rename, etag string) (*Operation[api.RenameResult], error) {
	return renameAt(ctx, r.c, r.item(name), req, etag)
}

func renameAt(ctx context.Context, c *Client, item string, req api.Rename, etag string) (*Operation[api.RenameResult], error) {
	if err := c.need("rename"); err != nil {
		return nil, err
	}
	h := http.Header{}
	if etag != "" {
		h.Set("If-Match", quoteETag(etag))
	}
	op, _, err := sendOp[api.RenameResult](ctx, c, request{method: http.MethodPost, path: item + "/rename", body: req, header: h}, nil)
	return op, err
}
