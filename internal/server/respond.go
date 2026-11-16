package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

func etagOf(gen int64) string { return `"` + strconv.FormatInt(gen, 10) + `"` }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sync writes a sync envelope.
func (c *rc) sync(status int, meta any, etag int64) {
	raw, err := json.Marshal(meta)
	if err != nil {
		c.fail(api.Errorf(api.CodeInternal, "encode reply: %v", err))
		return
	}
	if etag > 0 {
		c.w.Header().Set("ETag", etagOf(etag))
	}
	c.status = status
	writeJSON(c.w, status, api.Response{Type: api.ResponseSync, Status: "Success", StatusCode: status, Metadata: raw})
}

// async writes the 202 envelope of an operation.
func (c *rc) async(op api.Operation) {
	raw, _ := json.Marshal(op)
	loc := "/api/v1/operations/" + op.ID
	c.w.Header().Set("Location", loc)
	c.status = http.StatusAccepted
	writeJSON(c.w, http.StatusAccepted, api.Response{Type: api.ResponseAsync, Status: "Operation created", StatusCode: 202, Operation: loc, Metadata: raw})
}

// fail writes the error envelope for err.
func (c *rc) fail(err error) {
	var ae *api.Error
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		c.w.Header().Set("Retry-After", locked.RetryAfterSeconds())
		ae = api.Errorf(api.CodeRateLimited, "too many failed attempts").
			WithHint("try again in "+locked.RetryAfterSeconds()+" seconds").WithDetail("retry_after", locked.RetryAfterSeconds())
	case errors.As(err, &ae):
		if ae.Code == api.CodeInternal {
			// what the service wrapped (a store, helper or command error) can carry host paths and command output: it goes to
			// the daemon log under the request id, and the client gets the id
			c.s.log.Error("internal error", "rid", c.rid, "route", c.r.Method+" "+c.r.URL.Path, "err", ae.Message)
			ae = api.Errorf(api.CodeInternal, "internal error").WithHint("see the daemon log for request " + c.rid)
		}
	default:
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			ae = api.Errorf(api.CodeInvalid, "request body is larger than %d bytes", mb.Limit)
		} else {
			c.s.log.Error("internal error", "rid", c.rid, "route", c.r.Method+" "+c.r.URL.Path, "err", err)
			ae = api.Errorf(api.CodeInternal, "internal error").WithHint("see the daemon log for request " + c.rid)
		}
	}
	st := ae.Code.HTTPStatus()
	if c.statusOverride != 0 {
		st = c.statusOverride
	}
	c.status, c.code = st, ae.Code
	writeJSON(c.w, st, api.Response{Type: api.ResponseError, Status: "Failure", StatusCode: st, Error: ae})
}

// decode reads one JSON value from the body, strictly (strictjson.go).
func (c *rc) decode(v any) error {
	if err := c.jsonBody(); err != nil {
		return err
	}
	return c.decodeBody(v, false)
}

// decodeBody reads the body (bounded by the request's MaxBytesReader) and decodes it into v after the strict check.
// An empty body is io.EOF when optional is set.
func (c *rc) decodeBody(v any, optional bool) error {
	data, err := io.ReadAll(c.r.Body)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return err
		}
		return api.Errorf(api.CodeInvalid, "invalid request body: %v", err)
	}
	if optional && len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := checkStrict(data, v); err != nil {
		return api.Errorf(api.CodeInvalid, "invalid request body: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return api.Errorf(api.CodeInvalid, "invalid request body: %v", err)
	}
	return nil
}

// expect parses If-Match into a generation; absent or "*" means any.
func (c *rc) expect() (int64, error) {
	h := strings.TrimSpace(c.r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return service.AnyGeneration, nil
	}
	first, _, _ := strings.Cut(h, ",")
	first = strings.Trim(strings.TrimPrefix(strings.TrimSpace(first), "W/"), `"`)
	n, err := strconv.ParseInt(first, 10, 64)
	if err != nil || n < 0 {
		return 0, api.Errorf(api.CodeInvalid, "invalid If-Match %q", h)
	}
	return n, nil
}

// labels parses repeated ?label=k=v.
func (c *rc) labels() (map[string]string, error) {
	var out map[string]string
	for _, l := range c.r.URL.Query()["label"] {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, api.Errorf(api.CodeInvalid, "invalid label selector %q (use key=value)", l)
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out, nil
}

func (c *rc) pathArg(name string) string { return c.r.PathValue(name) }

var _ = fmt.Sprint

// jsonBody refuses a body that is not declared as JSON. A browser form can send text/plain or
// application/x-www-form-urlencoded across origins without a preflight; requiring application/json keeps a
// forged cross-site request out of every handler that reads a body.
func (c *rc) jsonBody() error {
	ct := c.r.Header.Get("Content-Type")
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
		return api.Errorf(api.CodeInvalid, "the request body must be application/json (got %q)", ct)
	}
	return nil
}
