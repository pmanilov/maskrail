// Modified in this fork: bound streaming audit capture before allocation and preserve UTF-8 boundaries.
package common

import (
	"strings"
	"unicode/utf8"
)

// MaskedResponseTextSource is optionally implemented by an SSE Processor to
// expose the accumulated pre-demask (placeholder-bearing) model response text
// at end-of-stream, for the audit trail. Callers type-assert it; processors
// that do not track it (e.g. the passthrough) simply do not implement it.
type MaskedResponseTextSource interface {
	MaskedResponseText() []string
}

// Capture limits apply to an entire response, not separately to each stream key.
// Independent key/entry caps also bound metadata when fragments are tiny.
const (
	maxCaptureBytes    = 64 * 1024
	maxCaptureKeys     = 1024
	maxCaptureKeyBytes = 64 * 1024
	maxCaptureKeyLen   = 256
)

// MaskedTextRecorder accumulates at most 64 KiB of masked (pre-demask) SSE
// response text across all stream keys in first-seen order. Capture truncation
// never affects the response sent to the client.
// It tracks only what the caller feeds it — tool-call argument fragments are
// deliberately not recorded (masked_response_texts is the model's text output).
// The zero value is ready to use; it is single-goroutine (SSE processing runs
// on one goroutine per stream).
type MaskedTextRecorder struct {
	byKey    map[string]*strings.Builder
	order    []string
	bytes    int
	keyBytes int
}

// Add appends a pre-demask text fragment for the given stream key. Empty
// fragments are ignored so buffering/flush no-ops do not create empty entries.
func (r *MaskedTextRecorder) Add(key, text string) {
	if text == "" || r.bytes >= maxCaptureBytes {
		return
	}
	if len(key) > maxCaptureKeyLen {
		return
	}
	b, ok := r.byKey[key]
	if !ok {
		if len(r.order) >= maxCaptureKeys || r.keyBytes+len(key) > maxCaptureKeyBytes {
			return
		}
	}
	remaining := maxCaptureBytes - r.bytes
	if len(text) > remaining {
		cut := remaining
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut]
	}
	if text == "" {
		return
	}
	if !ok {
		if r.byKey == nil {
			r.byKey = make(map[string]*strings.Builder)
		}
		key = strings.Clone(key)
		r.keyBytes += len(key)
		b = &strings.Builder{}
		r.byKey[key] = b
		r.order = append(r.order, key)
	}
	b.WriteString(text)
	r.bytes += len(text)
}

// Texts returns the accumulated masked text of each stream in first-seen order.
// Returns nil when nothing was recorded.
func (r *MaskedTextRecorder) Texts() []string {
	if len(r.order) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.order))
	for _, k := range r.order {
		if s := r.byKey[k].String(); s != "" {
			out = append(out, s)
		}
	}
	return out
}
