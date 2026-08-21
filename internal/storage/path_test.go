package storage

import (
	"errors"
	"testing"
)

func TestMapPathImages(t *testing.T) {
	key, err := MapPath("/i/foo/bar.png", false)
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}

	if key != "foo/bar.png" {
		t.Errorf("key = %q, want foo/bar.png", key)
	}
}

func TestMapPathAvatars(t *testing.T) {
	key, err := MapPath("/a/tenant/avatar.jpg", false)
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}

	if key != "tenant/avatar.jpg" {
		t.Errorf("key = %q, want tenant/avatar.jpg", key)
	}
}

func TestMapPathRegionVariant(t *testing.T) {
	key, err := MapPath("/i/r/us-east/foo/bar.png", true)
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "foo/bar.png" {
		t.Errorf("key = %q, want foo/bar.png", key)
	}
}

func TestMapPathRegionVariantDisabled(t *testing.T) {
	// When region paths are disabled, "/r/us-east" is treated as a literal key segment and preserved.

	key, err := MapPath("/i/r/us-east/foo/bar.png", false)
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}

	if key != "r/us-east/foo/bar.png" {
		t.Errorf("key = %q, want r/us-east/foo/bar.png", key)
	}
}

func TestMapPathTraversal(t *testing.T) {
	for _, p := range []string{
		"/i/../../etc/passwd",
		"/i/..%2f..%2fetc/passwd",
		"/a/%2e%2e/%2e%2e/secret",
		"/i/foo/../bar",
	} {
		if _, err := MapPath(p, false); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("MapPath(%q) error = %v, want ErrInvalidKey", p, err)
		}
	}
}

func TestMapPathInvalidPrefix(t *testing.T) {
	for _, p := range []string{
		"/x/foo",
		"/i",
		"/i/",
		"/",
	} {
		if _, err := MapPath(p, false); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("MapPath(%q) error = %v, want ErrInvalidKey", p, err)
		}
	}
}

func TestMapPathURLEncodedKey(t *testing.T) {
	// A key with a space, encoded in the request path.

	key, err := MapPath("/i/my%20file.png", false)
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}

	if key != "my file.png" {
		t.Errorf("key = %q, want \"my file.png\"", key)
	}
}

func TestMapStorageError(t *testing.T) {
	if err := MapStorageError("NoSuchKey"); !errors.Is(err, ErrNotFound) {
		t.Errorf("MapStorageError(NoSuchKey) = %v, want ErrNotFound", err)
	}

	if err := MapStorageError("AccessDenied"); !errors.Is(err, ErrForbidden) {
		t.Errorf("MapStorageError(AccessDenied) = %v, want ErrForbidden", err)
	}

	if err := MapStorageError("Whatever"); err == nil {
		t.Errorf("MapStorageError(Whatever) = nil, want non-nil")
	}
}

func TestParseErrorCode(t *testing.T) {
	body := `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>nope</Message></Error>`

	if got := parseErrorCode(body); got != "NoSuchKey" {
		t.Errorf("parseErrorCode() = %q, want NoSuchKey", got)
	}

	if got := parseErrorCode("<Error></Error>"); got != "" {
		t.Errorf("parseErrorCode() = %q, want empty", got)
	}
}
