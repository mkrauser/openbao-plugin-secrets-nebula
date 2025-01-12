package nebula

import "strings"

func formatFingerprint(s string) string {
	var result strings.Builder
	for i, c := range s {
		// Add the current character to the result
		result.WriteRune(c)

		// Add a colon after every 4th character (except after the last character)
		if (i+1)%4 == 0 && i != len(s)-1 {
			result.WriteRune(':')
		}
	}
	return result.String()
}
