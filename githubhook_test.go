package githubhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // GitHub uses SHA1.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pierrre/assert"
)

var testRawPayload = []byte(`{"foo":"bar"}`)

func TestHandlerJSON(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerForm(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form := make(url.Values)
	form.Set("payload", string(testRawPayload))
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerSecret(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, h.Secret, testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerDelivery(t *testing.T) {
	ctx := t.Context()
	deliveryCalled := false
	h := &Handler{
		Delivery: func(event string, deliveryId string, payload any) {
			deliveryCalled = true
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
	assert.True(t, deliveryCalled)
}

func TestHandlerDecodePayload(t *testing.T) {
	ctx := t.Context()
	decodePayloadCalled := false
	h := &Handler{
		DecodePayload: func(event string, rawPayload []byte) (any, error) {
			decodePayloadCalled = true
			return string(rawPayload), nil
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
	assert.True(t, decodePayloadCalled)
}

func TestHandlerError(t *testing.T) {
	ctx := t.Context()
	errorCalled := false
	h := &Handler{
		Error: func(err error, req *http.Request) {
			errorCalled = true
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
	assert.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusMethodNotAllowed)
	assert.True(t, errorCalled)
}

func TestHandlerErrorMethod(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
	assert.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusMethodNotAllowed)
}

func TestHandlerErrorHeaderEvent(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Del("X-GitHub-Event")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderDelivery(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Del("X-GitHub-Delivery")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderContentType(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Set("Content-Type", "foobar")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignature(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, h.Secret, testRawPayload)
	req.Header.Del("X-Hub-Signature")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureFormat(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, h.Secret, testRawPayload)
	req.Header.Set("X-Hub-Signature", "foobar")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureHex(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, h.Secret, testRawPayload)
	req.Header.Set("X-Hub-Signature", "sha1=zz")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureSecret(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, h.Secret, testRawPayload)
	testSignRequest(req, "wrong", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerSecretSHA256(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	testSignRequest256(req, h.Secret, testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerSecretSHA256Preferred(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	testSignRequest256(req, h.Secret, testRawPayload)
	testSignRequest(req, "wrong", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerErrorHeaderSignatureSHA256Format(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Set("X-Hub-Signature-256", "foobar")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureSHA256Hex(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	req.Header.Set("X-Hub-Signature-256", "sha256=zz")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureSHA256Secret(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	testSignRequest256(req, "wrong", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureSHA256Preferred(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(ctx, t, srv, "", testRawPayload)
	testSignRequest256(req, "wrong", testRawPayload)
	testSignRequest(req, h.Secret, testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorDecodePayload(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	rawPayload := []byte("not json")
	req := testNewJSONRequest(ctx, t, srv, h.Secret, rawPayload)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorInternal(t *testing.T) {
	ctx := t.Context()
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	assert.NoError(t, err)
	h := &Handler{}
	h.handleError(errors.New("internal error"), w, req)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
}

func TestRequestError(t *testing.T) {
	err := &RequestError{
		StatusCode: http.StatusTeapot,
		Message:    http.StatusText(http.StatusTeapot),
	}
	_ = err.Error()
}

func testNewJSONRequest(ctx context.Context, t *testing.T, srv *httptest.Server, secret string, rawPayload []byte) *http.Request {
	t.Helper()
	req := testNewRequest(ctx, t, srv, secret, rawPayload)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(rawPayload))
	return req
}

func testNewRequest(ctx context.Context, t *testing.T, srv *httptest.Server, secret string, rawPayload []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, http.NoBody)
	assert.NoError(t, err)
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", testGetRandomDeliveryID(t))
	if secret != "" {
		testSignRequest(req, secret, rawPayload)
	}
	return req
}

func testSignRequest(req *http.Request, secret string, rawPayload []byte) {
	testSignRequestHeader(req, "X-Hub-Signature", "sha1=", sha1.New, secret, rawPayload)
}

func testSignRequest256(req *http.Request, secret string, rawPayload []byte) {
	testSignRequestHeader(req, "X-Hub-Signature-256", "sha256=", sha256.New, secret, rawPayload)
}

func testSignRequestHeader(req *http.Request, headerName, prefix string, hashFunc func() hash.Hash, secret string, rawPayload []byte) {
	macHash := hmac.New(hashFunc, []byte(secret))
	_, _ = macHash.Write(rawPayload)
	mac := macHash.Sum(nil)
	signature := prefix + hex.EncodeToString(mac)
	req.Header.Set(headerName, signature)
}

func testGetRandomDeliveryID(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, buf)
	assert.NoError(t, err)
	return hex.EncodeToString(buf)
}

func testExpectResponseStatusOK(t *testing.T, resp *http.Response) {
	t.Helper()
	assert.Equal(t, http.StatusOK, resp.StatusCode, assert.MessageTransform(func(msg string) string {
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		return fmt.Sprintf("body=%s\n%s", string(body), msg)
	}))
}

func testExpectResponseStatus(t *testing.T, resp *http.Response, statusCode int) {
	t.Helper()
	assert.Equal(t, statusCode, resp.StatusCode)
}
