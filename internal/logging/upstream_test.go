// Modified in this fork: prevent URL credentials and remote error text leaking into logs.
package logging

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestURLOriginExcludesSensitiveComponents(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"https://canary-user:canary-password@example.org:8443/secret-path?token=canary-query#private", "https://example.org:8443"},
		{"http://[::1]:8080/path?secret=yes", "http://[::1]:8080"},
		{"https://user:secret@host/%invalid", "<invalid upstream>"},
		{"not-a-url?token=canary", "<invalid upstream>"},
		{"file:///private/secret", "<invalid upstream>"},
	} {
		if got := URLOrigin(tt.input); got != tt.want {
			t.Errorf("URLOrigin returned %q, want %q", got, tt.want)
		}
	}
}

func TestUpstreamErrorRetainsCategoryWithoutRemoteText(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want string
	}{
		{&url.Error{Op: "Post", URL: "http://canary-user:canary-password@example.org/?token=canary-query", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}, "connection refused"},
		{&url.Error{Op: "Get", URL: "https://example.org/?token=canary", Err: context.DeadlineExceeded}, "deadline exceeded"},
		{&url.Error{Op: "Get", URL: "https://example.org/?token=canary", Err: errors.New("redirect https://secret:canary@example.org/private")}, "transport failure (*url.Error)"},
		{errors.New("unwrapped remote secret canary"), "transport failure (*errors.errorString)"},
	} {
		got := UpstreamError(tt.err).Error()
		if got != tt.want || strings.Contains(got, "canary") {
			t.Errorf("unsafe or incorrect error category %q, want %q", got, tt.want)
		}
	}
}
