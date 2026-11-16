package server

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
)

// Request bodies are read strictly: a member the request type does not have, a member spelled with other cases
// ("Dry_Run" for "dry_run"), a member that appears twice and anything after the value are refused. A misspelled
// option is an error instead of a request that runs without it. The status of an object (a client that read it sends
// it back) is ignored. Maps (labels, configuration keys, merge patches)
// take any key, and values with their own decoding (json.RawMessage, custom unmarshalers) are not looked into.

// checkStrict walks the JSON in data along the type of v and reports the first member that would be dropped or
// guessed.
func checkStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkValue(dec, reflect.TypeOf(v), "", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected data after the JSON value")
	}
	return nil
}

var (
	unmarshalerType     = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// maxDepth bounds the nesting of a request body.
const maxDepth = 1000

// walkValue reads one value. t is the Go type it decodes into; nil reads it without checking.
func walkValue(dec *json.Decoder, t reflect.Type, path string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("the JSON value is nested deeper than %d levels", maxDepth)
	}
	for t != nil && t.Kind() == reflect.Pointer {
		if t.Implements(unmarshalerType) {
			t = nil
			break
		}
		t = t.Elem()
	}
	if t != nil && (reflect.PointerTo(t).Implements(unmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) ||
		t.Kind() == reflect.Interface) {
		t = nil
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, elem, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	case '{':
		var fields map[string]reflect.Type
		var folded map[string]string
		var elem reflect.Type
		structured := false
		if t != nil {
			switch t.Kind() {
			case reflect.Struct:
				fields, folded = structFields(t)
				structured = true
			case reflect.Map:
				elem = t.Elem()
			}
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			name := joinPath(path, k)
			if seen[k] {
				return fmt.Errorf("member %q appears twice", name)
			}
			seen[k] = true
			ft := elem
			if structured {
				var ok bool
				if ft, ok = fields[k]; !ok && depth == 0 && k == "status" && fields["metadata"] != nil {
					// an object read and sent back carries its status, which is observed, never desired: ignored
					ft, ok = nil, true
				}
				if !ok {
					if exact, ok := folded[strings.ToLower(k)]; ok {
						return fmt.Errorf("unknown member %q (the name is %q)", name, joinPath(path, exact))
					}
					return fmt.Errorf("unknown member %q", name)
				}
			}
			if err := walkValue(dec, ft, name, depth+1); err != nil {
				return err
			}
		}
	}
	// the closing delimiter
	_, err = dec.Token()
	return err
}

func joinPath(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

var fieldCache sync.Map // reflect.Type -> [2]any{map[string]reflect.Type, map[string]string}

// structFields returns the JSON member names of a struct type (with the members of embedded structs, as
// encoding/json promotes them) and, by lower-case name, the exact spelling.
func structFields(t reflect.Type) (map[string]reflect.Type, map[string]string) {
	if c, ok := fieldCache.Load(t); ok {
		p := c.([2]any)
		return p[0].(map[string]reflect.Type), p[1].(map[string]string)
	}
	fields := map[string]reflect.Type{}
	depth := map[string]int{}
	var collect func(t reflect.Type, level int)
	collect = func(t reflect.Type, level int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			ft := f.Type
			if f.Anonymous && name == "" {
				et := ft
				if et.Kind() == reflect.Pointer {
					et = et.Elem()
				}
				if et.Kind() == reflect.Struct {
					collect(et, level+1)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			if d, ok := depth[name]; ok && d <= level {
				continue
			}
			fields[name], depth[name] = ft, level
		}
	}
	collect(t, 0)
	folded := make(map[string]string, len(fields))
	for k := range fields {
		folded[strings.ToLower(k)] = k
	}
	fieldCache.Store(t, [2]any{fields, folded})
	return fields, folded
}
