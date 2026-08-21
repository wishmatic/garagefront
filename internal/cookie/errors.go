package cookie

import "errors"

var (
	ErrMissingKeyPairID = errors.New("Missing Key-Pair-Id")
	ErrAccessDenied     = errors.New("Access Denied")
)
