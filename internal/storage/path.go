package storage

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// MapPath converts a request URL path into an object key.
//
// LibreChat stores inline images/avatars under object keys that begin with the "i"/"a" namespace prefix, and its
// CloudFront URLs are just "<domain>/<key>". So the mapping is identity: the URL path (minus its leading slash) is
// the object key. The region/tenant segments, when present, appear in both the URL and the key identically.
//
//	URL  /i/r/us-east-2/t/tenantA/images/user123/file.png
//	key   i/r/us-east-2/t/tenantA/images/user123/file.png
//
// The only validation is that the path begins with a known namespace ("i" or "a") and contains no path-traversal
// segments.
func MapPath(p string) (string, error) {
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return "", fmt.Errorf("decode path: %w", err)
	}

	segments := splitPath(decoded)

	if slices.Contains(segments, "..") {
		return "", ErrInvalidKey
	}

	if len(segments) < 2 {
		return "", ErrInvalidKey
	}

	switch segments[0] {
	case "i", "a":
	default:
		return "", ErrInvalidKey
	}

	return strings.Join(segments, "/"), nil
}

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
