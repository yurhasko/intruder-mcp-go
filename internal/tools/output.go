package tools

import "unicode/utf8"

// jsonTextBytes reports the size of text as a JSON string value, quotes
// included. It mirrors encoding/json's escaping, HTML escaping included, so a
// result can be measured without marshaling a second copy of it.
func jsonTextBytes(text string) int {
	size := len(text) + 2 // The surrounding quotes.

	for i := 0; i < len(text); {
		c := text[i]
		i++

		switch {
		case c == '\\' || c == '"' || c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f':
			size++ // Becomes a two-byte escape.

		case c < 0x20 || c == '<' || c == '>' || c == '&':
			size += 5 // Becomes \u00XX.

		case c >= utf8.RuneSelf:
			r, n := utf8.DecodeRuneInString(text[i-1:])
			i += n - 1
			switch {
			case r == '\u2028' || r == '\u2029':
				size += 3
			case r == utf8.RuneError && n == 1:
				size += 2
			}
		}
	}
	return size
}

func outputBytes(text string) int {
	const envelope = `{"content":[{"type":"text","text":}]}`
	return len(envelope) + jsonTextBytes(text)
}
