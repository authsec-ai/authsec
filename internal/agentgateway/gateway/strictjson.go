package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// errAmbiguousJSON refuses a body that two JSON parsers could read
// differently.
var errAmbiguousJSON = errors.New("ambiguous JSON")

// maxJSONDepth bounds nesting so the walk itself cannot be driven deep.
const maxJSONDepth = 64

// checkUnambiguousJSON refuses a JSON document in which any object repeats a
// key, exactly or differing only in case.
//
// The gateway decides on what encoding/json reads -- it matches keys case
// insensitively and the last match wins -- but forwards the original bytes.
// An upstream with a case-sensitive parser that keeps the first key would
// otherwise execute {"name":"delete_repo","NAME":"get_me"} as delete_repo
// while the PDP and the decision log saw get_me. Refusing the ambiguity
// makes every parser read the same thing, so the decision is about the
// request that is forwarded.
func checkUnambiguousJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	// One frame per open container: keys (lower-cased) for an object, nil
	// for an array; expectKey is true where the next string is a key.
	type frame struct {
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("%w: nested deeper than %d", errAmbiguousJSON, maxJSONDepth)
				}
				if top != nil && top.keys != nil {
					top.expectKey = true // this container was the value
				}
				f := &frame{}
				if t == '{' {
					f.keys, f.expectKey = map[string]bool{}, true
				}
				stack = append(stack, f)
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].keys != nil {
					stack[len(stack)-1].expectKey = true
				}
			}
		case string:
			if top != nil && top.keys != nil && top.expectKey {
				k := strings.ToLower(t)
				if top.keys[k] {
					return fmt.Errorf("%w: the key %q appears more than once (keys are compared ignoring case)", errAmbiguousJSON, t)
				}
				top.keys[k] = true
				top.expectKey = false
				continue
			}
			if top != nil && top.keys != nil {
				top.expectKey = true
			}
		default:
			if top != nil && top.keys != nil {
				top.expectKey = true
			}
		}
	}
	return nil
}
