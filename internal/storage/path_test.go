package storage

import (
	"errors"
	"testing"
)

func TestMapPathIdentity(t *testing.T) {
	key, err := MapPath("/i/images/user123/file.png")
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "i/images/user123/file.png" {
		t.Errorf("key = %q, want i/images/user123/file.png", key)
	}
}

func TestMapPathRegionTenant(t *testing.T) {
	key, err := MapPath("/i/r/us-east-2/t/tenantA/images/user123/file.png")
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "i/r/us-east-2/t/tenantA/images/user123/file.png" {
		t.Errorf("key = %q, want i/r/us-east-2/t/tenantA/images/user123/file.png", key)
	}
}

func TestMapPathAvatar(t *testing.T) {
	key, err := MapPath("/a/r/ap-southeast-1/t/tenantA/avatars/user123/avatar.png")
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "a/r/ap-southeast-1/t/tenantA/avatars/user123/avatar.png" {
		t.Errorf("key = %q, want a/r/ap-southeast-1/t/tenantA/avatars/user123/avatar.png", key)
	}
}

func TestMapPathTraversal(t *testing.T) {
	// MapPath receives r.URL.Path, which net/http has already percent-decoded. So these inputs are the decoded form
	// of a client's %2e%2e/%2f request.

	for _, p := range []string{
		"/i/../../etc/passwd",
		"/a/../../secret",
		"/i/foo/../bar",
	} {
		if _, err := MapPath(p); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("MapPath(%q) error = %v, want ErrInvalidKey", p, err)
		}
	}
}

// TestMapPathDoubleEncodedTraversalIsLiteral confirms that a double-encoded traversal (net/http decodes %252e%252e
// once, leaving %2e%2e) is not itself decoded by MapPath and so is treated as a literal object key. It does not
// traverse; S3 treats the %-encoded segments as literal key characters.
func TestMapPathDoubleEncodedTraversalIsLiteral(t *testing.T) {
	key, err := MapPath("/i/%2e%2e/%2e%2e/secret")
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "i/%2e%2e/%2e%2e/secret" {
		t.Errorf("key = %q, want literal key", key)
	}
}

func TestMapPathInvalidPrefix(t *testing.T) {
	for _, p := range []string{
		"/x/foo",
		"/i",
		"/i/",
		"/",
	} {
		if _, err := MapPath(p); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("MapPath(%q) error = %v, want ErrInvalidKey", p, err)
		}
	}
}

func TestMapPathDecodedKey(t *testing.T) {
	// net/http decodes %20 before MapPath runs, so a client request for "/i/my%20file.png" arrives here as
	// "/i/my file.png".

	key, err := MapPath("/i/my file.png")
	if err != nil {
		t.Fatalf("MapPath() unexpected error: %v", err)
	}
	if key != "i/my file.png" {
		t.Errorf("key = %q, want \"i/my file.png\"", key)
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
