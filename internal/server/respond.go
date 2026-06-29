package server

import (
	"encoding/json"
	"net/http"
)

// writeJSON serializes v as JSON with the given status code. Every success body
// in app.py carries "ok": true; callers build that into v explicitly (mirroring
// jsonify({"ok": True, ...})) so this helper stays a thin, generic writer.
//
// On an (unexpected) encode failure the header is already committed, so there is
// nothing useful left to do but stop — matching Flask, which would 500 on a
// non-serializable payload. We never build non-serializable payloads here.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errJSON writes the standard error envelope {"ok": false, "error": msg} with the
// given status code — the Go form of jsonify({"ok": False, "error": ...}), status.
// Error strings passed in are copied verbatim from app.py so the web client's
// message handling is unchanged.
func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}

// readJSON decodes the request body into a map, tolerating an empty/invalid body
// (returns an empty map, never an error) — the analogue of Flask's
// request.get_json(silent=True) or {} / get_json(force=True, silent=True) or {}.
// app.py never distinguishes "force" from "silent" in any branch that matters
// (an invalid body always falls through to a missing-field 400), so one lenient
// decoder covers every call site.
func readJSON(r *http.Request) map[string]any {
	m := map[string]any{}
	if r.Body == nil {
		return m
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&m); err != nil {
		return map[string]any{}
	}
	return m
}

// strPtr returns &s, for the *string params LogAudit / RecordFailedAttempt take.
func strPtr(s string) *string { return &s }

// jsonBool reads a JSON bool field, returning (value, true) only when the field
// is present AND a real bool — matching Python's isinstance(enabled, bool) guard
// (a JSON number/string is NOT accepted as a bool). encoding/json decodes JSON
// booleans into Go bool, so a type assertion is the exact equivalent.
func jsonBool(m map[string]any, key string) (val bool, ok bool) {
	v, present := m[key]
	if !present {
		return false, false
	}
	b, isBool := v.(bool)
	return b, isBool
}

// jsonBoolDefault reads a JSON bool field with a fallback, mirroring
// data.get(key, default) coerced via bool(...): present truthy/falsey JSON bool
// wins, otherwise the default. Only a real JSON bool overrides the default here,
// which matches every app.py call site that uses bool(data.get(..., <default>))
// for an explicitly-boolean client field (enabled, is_admin, rotate_secret).
func jsonBoolDefault(m map[string]any, key string, def bool) bool {
	if b, ok := jsonBool(m, key); ok {
		return b
	}
	return def
}

// jsonString reads a JSON string field, returning "" when absent or non-string —
// the analogue of data.get(key, "") for the string fields app.py reads
// (username, group_name, secret, ...).
func jsonString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// jsonInt reads a JSON integer-ish field. JSON numbers decode to float64 through
// encoding/json, so it accepts a float64 (truncating to int, as int(port) does in
// Python) and a numeric string (Python int(port) also parses "8080"). Returns
// (0, false) when absent or unparseable, letting callers reproduce app.py's
// "port must be an integer" / "group_id is required" branches.
func jsonInt(m map[string]any, key string) (int, bool) {
	v, present := m[key]
	if !present || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64: // JSON numbers always decode to float64 through encoding/json
		return int(n), true
	case string: // Python int("8080") also parses a numeric string
		i, err := parseIntLenient(n)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}
