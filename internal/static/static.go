// Package static embeds the single-file web client (index.html) into the binary
// so the server has zero runtime asset dependencies — the Go analogue of Flask's
// send_from_directory(static_dir, "index.html"). The SPA is one self-contained
// HTML file (UI + admin console + PIN vault), so "/" serves it and there are no
// other asset paths to route.
package static

import (
	"embed"
	"net/http"
)

// indexFS holds the embedded index.html. Using embed.FS (rather than embedding
// the bytes directly into a string) keeps the directive valid even while the file
// is a placeholder; the operator overwrites index.html with the real SPA before
// building.
//
//go:embed index.html
var indexFS embed.FS

// Index is the raw bytes of the embedded web client, exposed for the server to
// serve directly (mirrors how Flask streamed the file from disk).
var Index = mustRead("index.html")

func mustRead(name string) []byte {
	b, err := indexFS.ReadFile(name)
	if err != nil {
		// An embed.FS read of an embedded path cannot fail at runtime once it
		// compiled, so this only fires if the embed directive and the constant
		// name drift apart — a build-time programming error, surfaced loudly.
		panic("static: embedded " + name + " missing: " + err.Error())
	}
	return b
}

// Handler serves the embedded SPA for "/" and returns 404 for any other path.
// The web client is a single file, so there is nothing else to route here; the
// API and /health are wired separately on the main mux.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(Index)
	})
}
