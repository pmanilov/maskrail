// Modified in this fork: exclude URL secrets and remote-controlled error text from diagnostics.
package logging

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
)

// URLOrigin keeps only the routing origin: no userinfo, path, query or fragment.
// Invalid URLs are never echoed, since parsing errors can contain credentials.
func URLOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "<invalid upstream>"
	}
	return u.Scheme + "://" + u.Host
}

// UpstreamError preserves a useful failure category without formatting arbitrary
// transport errors. Even an unwrapped error may embed URLs (e.g. redirect errors).
func UpstreamError(err error) error {
	if err == nil {
		return nil
	}
	var kind string
	switch {
	case errors.Is(err, context.Canceled):
		kind = "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		kind = "deadline exceeded"
	case errors.Is(err, syscall.ECONNREFUSED):
		kind = "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		kind = "connection reset"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			kind = "network timeout"
		} else {
			kind = fmt.Sprintf("transport failure (%T)", err)
		}
	}
	return errors.New(kind)
}
