// Modified in this fork: cover audit retention and update-only response enrichment.
package redis_test

import (
	"crypto/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/models"
	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/repository"
	redisrepo "github.com/cloud-ru-tech/guardrails-llm-filter/internal/repository/redis"
	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/repository/repositorytest"
	"github.com/cloud-ru-tech/guardrails-llm-filter/internal/repository/statecodec"
)

const (
	maskingTTL = 15 * time.Minute
	auditTTL   = 24 * time.Hour
)

func testCodec(t *testing.T) statecodec.Codec {
	t.Helper()
	key := make([]byte, statecodec.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	codec, err := statecodec.NewAESGCM(key)
	require.NoError(t, err)
	return codec
}

func runConformance(t *testing.T, codec statecodec.Codec) {
	var current *miniredis.Miniredis

	repositorytest.Run(t, func(t *testing.T) repository.Store {
		mr := miniredis.RunT(t)
		current = mr
		s := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, codec)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		return s
	}, repositorytest.Options{
		ExpireMaskingState: func(t *testing.T) {
			current.FastForward(maskingTTL + time.Second)
		},
		ExpireAudit: func(t *testing.T) {
			current.FastForward(auditTTL + time.Second)
		},
	})
}

func TestConformance(t *testing.T) {
	runConformance(t, statecodec.Plain())
}

// TestConformanceEncrypted runs the same suite with at-rest encryption on:
// the codec must be transparent to every store contract.
func TestConformanceEncrypted(t *testing.T) {
	runConformance(t, testCodec(t))
}

func sampleState() models.MaskingState {
	return models.MaskingState{
		TriggeredRuleIDs:   []string{"email"},
		TriggeredDataTypes: []models.DataType{models.DataTypePERSONALDATA},
		Replacements: []models.Replacement{
			{RuleID: "email", Original: "user@example.com", Placeholder: "<EMAIL_1>"},
		},
	}
}

func TestEncryptionAtRest(t *testing.T) {
	ctx := t.Context()
	mr := miniredis.RunT(t)
	s := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, testCodec(t))
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	require.NoError(t, s.PutMaskingState(ctx, "req-1", sampleState()))

	raw, err := mr.Get("guardrails:mask:req-1")
	require.NoError(t, err)
	assert.NotContains(t, raw, "user@example.com", "original must not be stored in plaintext")
	assert.Contains(t, raw, `"_enc":"aes256gcm"`)
}

func TestLegacyPlaintextRead(t *testing.T) {
	ctx := t.Context()
	mr := miniredis.RunT(t)
	codec := testCodec(t)

	// A plaintext record written before encryption was enabled.
	plain := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, statecodec.Plain())
	require.NoError(t, plain.PutMaskingState(ctx, "req-legacy", sampleState()))
	require.NoError(t, plain.Close())

	encrypted := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, codec)
	t.Cleanup(func() { require.NoError(t, encrypted.Close()) })
	got, err := encrypted.GetMaskingState(ctx, "req-legacy")
	require.NoError(t, err)
	assert.Equal(t, sampleState(), got)
}

func TestEncryptedRecordWithEncryptionDisabled(t *testing.T) {
	ctx := t.Context()
	mr := miniredis.RunT(t)

	encrypted := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, testCodec(t))
	require.NoError(t, encrypted.PutMaskingState(ctx, "req-1", sampleState()))
	require.NoError(t, encrypted.Close())

	plain := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, statecodec.Plain())
	t.Cleanup(func() { require.NoError(t, plain.Close()) })
	_, err := plain.GetMaskingState(ctx, "req-1")
	require.ErrorIs(t, err, repository.ErrUndecryptable)
}

func TestAuditResponseTextsPreservesRetention(t *testing.T) {
	ctx := t.Context()
	mr := miniredis.RunT(t)
	s := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, statecodec.Plain())
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	rec := models.AuditRecord{
		RequestID: "response-retention",
		Timestamp: time.Now().UTC().Truncate(time.Microsecond),
		Model:     "original-model",
	}
	require.NoError(t, s.PutAuditRecord(ctx, rec))
	key := "guardrails:audit:rec:" + rec.RequestID
	mr.FastForward(time.Hour)
	remaining := mr.TTL(key)
	require.Equal(t, auditTTL-time.Hour, remaining)

	rec.MaskedResponseTexts = []string{"masked answer"}
	require.NoError(t, s.SetAuditResponseTexts(ctx, rec.RequestID, rec.MaskedResponseTexts))
	got, err := s.GetAuditRecord(ctx, rec.RequestID)
	require.NoError(t, err)
	assert.Equal(t, rec, got)
	assert.Equal(t, remaining, mr.TTL(key), "enrichment must not reset or remove the TTL")
	assert.True(t, mr.Exists("guardrails:audit:idx"), "enrichment must leave the index intact")

	mr.FastForward(remaining)
	_, err = s.GetAuditRecord(ctx, rec.RequestID)
	require.ErrorIs(t, err, repository.ErrNotFound)
	assert.False(t, mr.Exists(key))
}

func TestAuditResponseTextsDoesNotResurrect(t *testing.T) {
	for _, scenario := range []string{"missing", "expired before read", "expired between read and write"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			mr := miniredis.RunT(t)
			s := redisrepo.New(redisrepo.Config{Addr: mr.Addr()}, maskingTTL, auditTTL, statecodec.Plain())
			t.Cleanup(func() { require.NoError(t, s.Close()) })
			const requestID = "expired-response"
			const key = "guardrails:audit:rec:" + requestID
			if scenario != "missing" {
				require.NoError(t, s.PutAuditRecord(ctx, models.AuditRecord{
					RequestID: requestID,
					Timestamp: time.Now().UTC(),
				}))
			}
			if scenario == "expired before read" {
				mr.FastForward(auditTTL)
			}
			var intercepted atomic.Bool
			if scenario == "expired between read and write" {
				// Expire after GET has returned but before the real Redis SET runs.
				// Intercept only the first write to this record.
				mr.Server().SetPreHook(func(_ *server.Peer, cmd string, args ...string) bool {
					if strings.EqualFold(cmd, "SET") && len(args) > 0 && args[0] == key && intercepted.CompareAndSwap(false, true) {
						mr.FastForward(auditTTL)
					}
					return false
				})
			}

			err := s.SetAuditResponseTexts(ctx, requestID, []string{"masked answer"})
			require.ErrorIs(t, err, repository.ErrNotFound)
			if scenario == "expired between read and write" {
				require.True(t, intercepted.Load(), "the test must exercise expiry after the read")
			}
			assert.False(t, mr.Exists(key), "response enrichment must never recreate an expired or missing record")
			_, err = s.GetAuditRecord(ctx, requestID)
			require.ErrorIs(t, err, repository.ErrNotFound)
		})
	}
}
