// Modified in this fork: enforce same-origin mutations and JSON media types without buffering management bodies.
package app

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// managementSecurity wraps only the API, never embedded console assets. It
// compares Origin authority to Host, not client-controlled forwarding headers.
// Reverse proxies must preserve browser-facing Host; TLS termination is allowed.
func managementSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !managementSafeMethod(r.Method) && !managementSameOrigin(r) {
			http.Error(w, "cross-origin management request denied", http.StatusForbidden)
			return
		}
		if managementJSONMethod(r.Method) && !managementJSONContentType(r.Header) {
			hasBody, err := managementHasBody(r)
			if err != nil {
				http.Error(w, "cannot read management request body", http.StatusBadRequest)
				return
			}
			if hasBody {
				http.Error(w, "management request requires application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// managementHasBody probes only bodies whose length is not known. Replaying the
// byte leaves the stream intact, and Close still closes the original body.
func managementHasBody(r *http.Request) (bool, error) {
	if r.ContentLength > 0 {
		return true, nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return false, nil
	}
	var first [1]byte
	n, err := io.ReadFull(r.Body, first[:])
	if n > 0 {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(first[:n]), r.Body), r.Body}
		return true, nil
	}
	if err == io.EOF {
		return false, nil
	}
	return false, err
}

func managementSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func managementJSONMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func managementJSONContentType(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return false
	}
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json") && len(mediaType) > len("application/+json"))
}

func managementSameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) > 0 {
		if len(origins) != 1 {
			return false
		}
		origin, ok := managementOrigin(origins[0])
		if !ok {
			return false
		}
		scheme, _, _ := strings.Cut(origins[0], "://") // Already validated above.
		target, ok := managementOrigin(scheme + "://" + r.Host)
		return ok && origin == target
	}
	// Non-browser CLI clients omit both headers. Fetch Metadata alone must
	// not authorize a request explicitly marked cross-site or same-site.
	sites := r.Header.Values("Sec-Fetch-Site")
	return len(sites) == 0 || (len(sites) == 1 && (sites[0] == "same-origin" || sites[0] == "none"))
}

// A normalized origin includes scheme, hostname and effective port. The
// standard CrossOriginProtection compares authorities literally, whereas this
// API also needs equivalent explicit/default ports to compare equal.
func managementOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(raw, "?#") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return u.Scheme + "://" + host + ":" + strconv.Itoa(n), true
}
