// Modified in this fork: exercise management origin and media-type checks without imposing body size limits.
package app

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestManagementSecurityOrigins(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		host       string
		origin     string
		site       string
		secure     bool
		forwarded  string
		wantStatus int
	}{
		{name: "CLI JSON", wantStatus: 204},
		{name: "same origin", origin: "http://console.example", wantStatus: 204},
		{name: "default HTTP port", origin: "http://console.example:80", wantStatus: 204},
		{name: "explicit host default port", host: "console.example:80", origin: "http://console.example", wantStatus: 204},
		{name: "case insensitive host", origin: "http://CONSOLE.example", wantStatus: 204},
		{name: "TLS", secure: true, origin: "https://console.example", wantStatus: 204},
		{name: "default HTTPS port", secure: true, origin: "https://console.example:443", wantStatus: 204},
		{name: "IPv6 default port", host: "[::1]:80", origin: "http://[::1]", wantStatus: 204},
		{name: "Vite preserved host", host: "localhost:5173", origin: "http://localhost:5173", wantStatus: 204},
		{name: "same origin overrides metadata", origin: "http://console.example", site: "cross-site", wantStatus: 204},
		{name: "CLI metadata none", site: "none", wantStatus: 204},
		{name: "browser same origin metadata", site: "same-origin", wantStatus: 204},
		{name: "cross origin", origin: "http://evil.example", wantStatus: 403},
		{name: "suffix spoof", origin: "http://console.example.evil.example", wantStatus: 403},
		{name: "userinfo spoof", origin: "http://console.example@evil.example", wantStatus: 403},
		{name: "userinfo on matching host", origin: "http://user@console.example", wantStatus: 403},
		{name: "null origin", origin: "null", wantStatus: 403},
		{name: "malformed", origin: ":bad", wantStatus: 403},
		{name: "multiple origin tokens", origin: "http://console.example http://evil.example", wantStatus: 403},
		{name: "origin path", origin: "http://console.example/", wantStatus: 403},
		{name: "origin query", origin: "http://console.example?", wantStatus: 403},
		{name: "origin fragment", origin: "http://console.example#", wantStatus: 403},
		{name: "invalid port", origin: "http://console.example:99999", wantStatus: 403},
		{name: "empty port", origin: "http://console.example:", wantStatus: 403},
		{name: "port mismatch", origin: "http://console.example:9080", wantStatus: 403},
		{name: "scheme difference is proxy compatible", secure: true, origin: "http://console.example", wantStatus: 204},
		{name: "HTTPS terminated upstream", origin: "https://console.example", wantStatus: 204},
		{name: "forwarding headers cannot authorize hostile host", origin: "https://evil.example", forwarded: "https", wantStatus: 403},
		{name: "cross-site without origin", site: "cross-site", wantStatus: 403},
		{name: "same-site without origin", site: "same-site", wantStatus: 403},
		{name: "hostile origin cannot use same origin metadata", origin: "http://evil.example", site: "same-origin", wantStatus: 403},
		{name: "unsafe delete", method: http.MethodDelete, origin: "http://evil.example", wantStatus: 403},
		{name: "safe get", method: http.MethodGet, origin: "http://evil.example", wantStatus: 204},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			r := httptest.NewRequest(method, "http://console.example/v1/rules", strings.NewReader(`{"rule_id":"test"}`))
			if tt.host != "" {
				r.Host = tt.host
			}
			if tt.secure {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("Content-Type", "application/json")
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if tt.site != "" {
				r.Header.Set("Sec-Fetch-Site", tt.site)
			}
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwarded)
				r.Header.Set("Forwarded", "proto="+tt.forwarded+";host=console.example")
			}
			assertManagementStatus(t, r, tt.wantStatus)
		})
	}
}

func TestManagementSecurityJSONMediaTypes(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		for _, tt := range []struct {
			mediaType string
			want      int
		}{
			{"application/json", 204},
			{"application/json; charset=utf-8", 204},
			{"application/merge-patch+json", 204},
			{"Application/JSON", 204},
			{"", 415},
			{"text/plain", 415},
			{"application/x-www-form-urlencoded", 415},
			{"application/+json", 415},
			{"application/json; broken", 415},
		} {
			t.Run(method+"/"+tt.mediaType, func(t *testing.T) {
				r := httptest.NewRequest(method, "/v1/rules", strings.NewReader(`{"rule_id":"canary"}`))
				if tt.mediaType != "" {
					r.Header.Set("Content-Type", tt.mediaType)
				}
				assertManagementStatus(t, r, tt.want)
			})
		}
	}
	t.Run("hostile simple POST cannot mutate", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "http://console.example/v1/rules", strings.NewReader(`{"rule_id":"canary"}`))
		r.Header.Set("Origin", "http://evil.example")
		r.Header.Set("Content-Type", "text/plain")
		assertManagementStatus(t, r, http.StatusForbidden)
	})
	t.Run("empty body without media type", func(t *testing.T) {
		assertManagementStatus(t, httptest.NewRequest(http.MethodPost, "/v1/rules", nil), http.StatusNoContent)
	})
	t.Run("empty Origin header is malformed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/rules", nil)
		r.Header["Origin"] = []string{""}
		assertManagementStatus(t, r, http.StatusForbidden)
	})
	t.Run("safe empty GET is not buffered", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
		r.Body = http.NoBody
		handler := managementSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != http.NoBody {
				t.Error("empty GET body was replaced")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status=%d", w.Code)
		}
	})
	for _, header := range []string{"Origin", "Sec-Fetch-Site", "Content-Type"} {
		t.Run("duplicate "+header, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://console.example/v1/rules", strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			value := "http://console.example"
			if header == "Sec-Fetch-Site" {
				value = "same-origin"
			} else if header == "Content-Type" {
				value = "application/json"
			}
			r.Header[header] = []string{value, value}
			status := http.StatusForbidden
			if header == "Content-Type" {
				status = http.StatusUnsupportedMediaType
			}
			assertManagementStatus(t, r, status)
		})
	}
}

func TestManagementSecurityPreservesLargeBodies(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", (4<<20)+1) + `"}`
	for _, unknown := range []bool{false, true} {
		name := "known"
		if unknown {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if unknown {
				r.ContentLength = -1
				r.TransferEncoding = []string{"chunked"}
			}
			length := r.ContentLength
			source := &managementCountingBody{reader: r.Body}
			r.Body = source
			called := false
			handler := managementSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if source.read != 0 || source.closed {
					t.Errorf("middleware consumed body: read=%d closed=%v", source.read, source.closed)
				}
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != body {
					t.Errorf("body changed: bytes=%d error=%v", len(got), err)
				}
				if r.ContentLength != length || (unknown && (len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked")) {
					t.Error("request framing changed")
				}
				if err := r.Body.Close(); err != nil || !source.closed {
					t.Errorf("original body was not closed: closed=%v error=%v", source.closed, err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent || !called {
				t.Fatalf("status=%d called=%v", w.Code, called)
			}
		})
	}
}

func TestManagementSecurityBodyProbe(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		for _, length := range []int64{-1, 0} {
			for _, body := range []string{"", `{"rule_id":"canary"}`} {
				t.Run(method+"/"+http.StatusText(map[bool]int{true: 415, false: 204}[body != ""])+"/length="+strconv.FormatInt(length, 10), func(t *testing.T) {
					r := httptest.NewRequest(method, "/v1/rules", nil)
					source := &managementCountingBody{reader: strings.NewReader(body)}
					r.Body, r.ContentLength = source, length
					if length == -1 {
						r.TransferEncoding = []string{"chunked"}
					}
					want := http.StatusNoContent
					if body != "" {
						want = http.StatusUnsupportedMediaType
					}
					assertManagementStatus(t, r, want)
					if source.read != min(1, len(body)) || source.closed {
						t.Fatalf("probe read=%d closed=%v", source.read, source.closed)
					}
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != body || r.ContentLength != length {
						t.Fatalf("probe changed body: body=%q length=%d error=%v", got, r.ContentLength, err)
					}
					if err := r.Body.Close(); err != nil || !source.closed {
						t.Fatalf("original body was not closed: closed=%v error=%v", source.closed, err)
					}
				})
			}
		}
	}
	t.Run("positive content length needs no probe", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
		r.ContentLength = 10
		assertManagementStatus(t, r, http.StatusUnsupportedMediaType)
	})
	t.Run("known body is not read", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
		source := &managementCountingBody{fail: true}
		r.Body, r.ContentLength = source, 10
		assertManagementStatus(t, r, http.StatusUnsupportedMediaType)
		if source.closed {
			t.Fatal("middleware closed body")
		}
	})
	t.Run("body probe failure", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
		r.Body = &managementCountingBody{fail: true}
		assertManagementStatus(t, r, http.StatusBadRequest)
	})
}

func assertManagementStatus(t *testing.T, r *http.Request, want int) {
	t.Helper()
	mutations := 0
	handler := managementSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mutations++
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != want || mutations != map[bool]int{true: 1, false: 0}[want == http.StatusNoContent] {
		t.Fatalf("status=%d downstream calls=%d, want status=%d", w.Code, mutations, want)
	}
}

type managementCountingBody struct {
	reader io.Reader
	read   int
	closed bool
	fail   bool
}

func (b *managementCountingBody) Read(p []byte) (int, error) {
	if b.fail {
		return 0, errors.New("synthetic body read failure")
	}
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *managementCountingBody) Close() error {
	b.closed = true
	return nil
}
