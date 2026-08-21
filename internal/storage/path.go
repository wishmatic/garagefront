package storage

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// MapPath converts a request URL path into an object key.
//
// Served prefixes are "/i/" (images) and "/a/" (avatars). When includeRegionInPath is true, the path may additionally
// carry a region segment "/r/<region>/" immediately after the prefix, which is stripped from the key.
func MapPath(p string, includeRegionInPath bool) (string, error) {
	// Decode the path. Reject malformed percent-encoding.

	decoded, err := url.PathUnescape(p)
	if err != nil {
		return "", fmt.Errorf("decode path: %w", err)
	}

	// Reject any remaining traversal.

	if strings.Contains(decoded, "..") {
		return "", ErrInvalidKey
	}

	segments := splitPath(decoded)

	// Expect at least a prefix and one key segment.

	if len(segments) < 2 {
		return "", ErrInvalidKey
	}

	switch segments[0] {
	case "i", "a":
	default:
		return "", ErrInvalidKey
	}

	rest := segments[1:]
	if includeRegionInPath {
		if len(rest) >= 2 && rest[0] == "r" {
			rest = rest[2:]
		}
	}

	if len(rest) == 0 {
		return "", ErrInvalidKey
	}

	return path.Join(rest...), nil
}

// splitPath splits on "/" and drops empty segments (leading/trailing/double slashes), so "/i/a/b/" and "/i//a/b"
// behave consistently.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
