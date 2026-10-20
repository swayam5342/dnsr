package term

import (
	"fmt"
	"strings"
)

const (
	Dim, Cyan, Green, Yellow, Red, Bold, Reset = "\033[2m", "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"
)

func Paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + Printable(s) + Reset
}

// Printable escapes bytes that could act as terminal control sequences.
func Printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			var b strings.Builder
			for j := 0; j < len(s); j++ {
				if c := s[j]; c < 0x20 || c == 0x7f {
					fmt.Fprintf(&b, "\\%03d", c)
				} else {
					b.WriteByte(c)
				}
			}
			return b.String()
		}
	}
	return s
}
