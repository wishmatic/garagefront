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
	for _, p := range []string{
		"/i/../../etc/passwd",
		"/i/..%2f..%2fetc/passwd",
		"/a/%2e%2e/%2e%2e/secret",
		"/i/foo/../bar",
	} {
		if _, err := MapPath(p); !errors.Is(err, ErrInvalidKey) {
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
		if _, err := MapPath(p); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("MapPath(%q) error = %v, want ErrInvalidKey", p, err)
		}
	}
}

func TestMapPathURLEncodedKey(t *testing.T) {
	key, err := MapPath("/i/my%20file.png")
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
