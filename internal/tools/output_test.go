package tools

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// outputBytes reimplements JSON escaping, so it is fuzzed against the real
// encoder. The seeds cover everything that costs more than one byte.
func FuzzOutputSize(f *testing.F) {
	for _, text := range []string{"", "plain", "\x00\n\t\"\\<>&", "\u2028\u2029", "\xff", "\ufffd"} {
		f.Add(text)
	}

	f.Fuzz(func(t *testing.T, text string) {
		result := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}

		if got := outputBytes(text); got != len(encoded) {
			t.Fatalf("output size = %d, want %d for %q", got, len(encoded), text)
		}
	})
}

func TestEscapedOutputLimit(t *testing.T) {
	cs := session(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":           strings.Repeat("<", 20), // Angle brackets are escaped, so each one costs six bytes.
			"authenticated_as": "user",
		})
	}, Options{MaxOutputBytes: 100})

	result := call(t, cs, "get_status", nil)
	if !result.IsError || !strings.Contains(resultText(t, result), "output exceeded") {
		t.Fatalf("result = %+v", result)
	}
}
