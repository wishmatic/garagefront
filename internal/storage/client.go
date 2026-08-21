package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// emptySHA256 is the hex-encoded SHA-256 digest of an empty payload, used as the payload hash when signing body-less
// GET/HEAD requests.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type Object struct {
	Body         io.ReadCloser
	ContentType  string
	ContentLen   int64
	ETag         string
	LastModified string
}

type Client struct {
	endpoint    string
	bucket      string
	region      string
	signer      *v4.Signer
	credentials aws.Credentials
	http        *http.Client
}

func NewClient(endpoint, bucket, region, accessKey, secretKey string) *Client {
	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}
	return &Client{
		endpoint:    strings.TrimRight(endpoint, "/"),
		bucket:      bucket,
		region:      region,
		signer:      v4.NewSigner(),
		credentials: creds,
		http:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Get(ctx context.Context, key string) (*Object, error) {
	req, err := c.buildRequest(ctx, http.MethodGet, key)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &Object{
			Body:         resp.Body,
			ContentType:  resp.Header.Get("Content-Type"),
			ContentLen:   resp.ContentLength,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}, nil
	}

	defer resp.Body.Close()
	return nil, c.statusError(resp)
}

func (c *Client) Head(ctx context.Context, key string) (*Object, error) {
	req, err := c.buildRequest(ctx, http.MethodHead, key)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		resp.Body.Close()
		return &Object{
			ContentType:  resp.Header.Get("Content-Type"),
			ContentLen:   resp.ContentLength,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}, nil
	}

	defer resp.Body.Close()
	return nil, c.statusError(resp)
}

func (c *Client) buildRequest(ctx context.Context, method, key string) (*http.Request, error) {
	urlStr := fmt.Sprintf("%s/%s/%s", c.endpoint, c.bucket, escapeKey(key))

	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	err = c.signer.SignHTTP(ctx, c.credentials, req, emptySHA256, "s3", c.region, time.Now())
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	return req, nil
}

func escapeKey(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func (c *Client) statusError(resp *http.Response) error {
	code := resp.Header.Get("X-Amz-Error-Code")
	if code == "" {
		if body, err := io.ReadAll(io.LimitReader(resp.Body, 4096)); err == nil {
			code = parseErrorCode(string(body))
		}
	}

	switch code {
	case "NoSuchKey":
		return ErrNotFound
	case "AccessDenied":
		return ErrForbidden
	case "":
		// Could not determine a code; use status as fallback.

		switch resp.StatusCode {
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusForbidden:
			return ErrForbidden
		}
	}

	return fmt.Errorf("upstream storage error: status %d (code %q)", resp.StatusCode, code)
}

func parseErrorCode(body string) string {
	start := strings.Index(body, "<Code>")
	if start == -1 {
		return ""
	}

	start += len("<Code>")

	end := strings.Index(body[start:], "</Code>")
	if end == -1 {
		return ""
	}

	return body[start : start+end]
}

func MapStorageError(code string) error {
	switch code {
	case "NoSuchKey":
		return ErrNotFound
	case "AccessDenied":
		return ErrForbidden
	default:
		return errors.New("unknown storage error")
	}
}
