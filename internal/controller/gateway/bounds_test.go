// Modified in this fork: cover opt-in bounded SSE audit capture and complete streaming delivery.
package gateway_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/controller/gateway"
	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/guardrails/demask"
	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/models"
)

func TestSSEAuditCaptureBoundedAndClientComplete(t *testing.T) {
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprintf("capture=%t", capture), func(t *testing.T) {
			text := strings.Repeat("x", 4096)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"start\"}}]}\n\n")
				w.(http.Flusher).Flush()
				for range 20 {
					_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", text)
				}
				_, _ = io.WriteString(w, "data: [DONE]\n\n")
			}))
			defer upstream.Close()
			cfg := testConfig(upstream.URL)
			cfg.Audit.StoreMaskedResponseTexts = capture
			audit := &fakeAudit{}
			h, err := gateway.New(cfg, &fakeMasker{reps: []models.Replacement{emailRep()}}, &fakeSettings{global: enforceSettings()}, demask.NewProvider(fakeDemaskReg{}, fakeScanner{}), audit)
			require.NoError(t, err)
			server := httptest.NewServer(h)
			defer server.Close()
			resp, err := server.Client().Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"alice@example.com"}]}`))
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), "[DONE]")
			var output strings.Builder
			for _, line := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(line, "data: {") {
					continue
				}
				var chunk struct {
					Choices []struct {
						Delta struct{ Content string }
					}
				}
				require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk))
				for _, choice := range chunk.Choices {
					output.WriteString(choice.Delta.Content)
				}
			}
			assert.Equal(t, "start"+strings.Repeat(text, 20), output.String(), "audit truncation must not truncate client output")
			server.Close() // wait for the response-capture callback after the final write
			if capture {
				require.Len(t, audit.responseTexts, 1)
				for _, texts := range audit.responseTexts {
					assert.Equal(t, 64*1024, len(strings.Join(texts, "")))
				}
			} else {
				assert.Empty(t, audit.responseTexts)
			}
		})
	}
}

func TestTransparentRelayStreams(t *testing.T) {
	firstReceived := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-firstReceived:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "last")
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL)
	h, err := gateway.New(cfg, &fakeMasker{}, &fakeSettings{global: enforceSettings()}, demask.NewProvider(fakeDemaskReg{}, fakeScanner{}), nil)
	require.NoError(t, err)
	server := httptest.NewServer(h)
	defer server.Close()
	server.Client().Timeout = 2 * time.Second
	resp, err := server.Client().Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[]}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	first := make([]byte, 5)
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err)
	assert.Equal(t, "first", string(first))
	close(firstReceived)
	rest, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "last", string(rest))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestBufferedResponseCaptureDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"<EMAIL_1>"}}]}`)
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL)
	cfg.Audit.StoreMaskedResponseTexts = false
	audit := &fakeAudit{}
	h, err := gateway.New(cfg, &fakeMasker{reps: []models.Replacement{emailRep()}}, &fakeSettings{global: enforceSettings()}, demask.NewProvider(fakeDemaskReg{}, fakeScanner{}), audit)
	require.NoError(t, err)
	resp := doPost(t, h, "/v1/chat/completions", fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, emailRep().Original), nil)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), emailRep().Original)
	assert.Empty(t, audit.responseTexts)
}
