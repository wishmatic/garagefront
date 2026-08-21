package storage

import "errors"

var (
	ErrNotFound   = errors.New("object not found")
	ErrForbidden  = errors.New("access denied")
	ErrInvalidKey = errors.New("invalid object key")
)
