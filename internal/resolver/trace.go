package resolver

import (
	"fmt"
	"strings"

	"github.com/swayam5342/dnsr/internal/term"
)

func (r *Resolver) c(code, s string) string {
	return term.Paint(r.Color, code, s)
}

// tracef prints one trace line; control characters from untrusted names are escaped.
func (r *Resolver) tracef(depth int, format string, a ...any) {
	if r.Trace == nil {
		return
	}
	for i, v := range a {
		if s, ok := v.(string); ok && !strings.HasPrefix(s, "\033") {
			a[i] = term.Printable(s)
		}
	}
	fmt.Fprintf(r.Trace, "%s%s\n", strings.Repeat("  │ ", depth), fmt.Sprintf(format, a...))
}

func summarize(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(s[:n], ", "), len(s)-n)
}
