package wire

import "strings"

func Fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// IsSubdomain reports whether child is at or below parent ("a.b.c." under "b.c.").
func IsSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	return child == parent || strings.HasSuffix(child, "."+parent)
}

// SplitLabels returns the labels of a name, without the root ("www.example.com." → www, example, com).
func SplitLabels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// ParentName drops the leftmost label ("www.example.com." → "example.com.").
func ParentName(name string) string {
	ls := SplitLabels(name)
	if len(ls) <= 1 {
		return "."
	}
	return strings.Join(ls[1:], ".") + "."
}
