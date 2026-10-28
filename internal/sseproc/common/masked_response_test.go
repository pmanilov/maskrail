// Modified in this fork: verify aggregate capture budgets and UTF-8-safe truncation.
package common

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskedTextRecorderAggregateBudget(t *testing.T) {
	var r MaskedTextRecorder
	r.Add("first", strings.Repeat("a", maxCaptureBytes-3))
	r.Add("second", "юю")
	r.Add("third", "z")
	r.Add("ignored", "overflow")
	texts := r.Texts()
	require.Len(t, texts, 3)
	assert.Equal(t, "ю", texts[1])
	assert.Equal(t, "z", texts[2])
	assert.Equal(t, maxCaptureBytes, r.bytes)
	for _, text := range texts {
		assert.True(t, utf8.ValidString(text))
	}
}

func TestMaskedTextRecorderMetadataBudgets(t *testing.T) {
	var r MaskedTextRecorder
	r.Add(strings.Repeat("k", maxCaptureKeyLen+1), "ignored")
	assert.Nil(t, r.Texts())
	for i := range 2 * maxCaptureKeys {
		r.Add(strconv.Itoa(i), "x")
	}
	assert.Len(t, r.Texts(), maxCaptureKeys)
	r.Add("0", "tail")
	assert.Equal(t, "xtail", r.Texts()[0], "existing streams can use remaining text budget")

	var longKeys MaskedTextRecorder
	for i := range maxCaptureKeys {
		longKeys.Add(strconv.Itoa(i)+strings.Repeat("k", 250), "x")
	}
	assert.LessOrEqual(t, longKeys.keyBytes, maxCaptureKeyBytes)
	assert.Less(t, len(longKeys.Texts()), maxCaptureKeys)
}
