package githubhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // GitHub uses SHA1.
	"encoding/hex"
	"errors"
	"fmt"
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, "", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, testRawPayload)
	testSignRequest(req, "wrong", testRawPayload)
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
	req := testNewJSONRequest(ctx, t, srv.URL, h.Secret, rawPayload)
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

func TestHandlerMaxBodySize(t *testing.T) {
	ctx := t.Context()
	h := &Handler{
		Secret:      "foobar",
		MaxBodySize: int64(len(testRawPayload)),
	}
	w := httptest.NewRecorder()
	req := testNewJSONRequest(ctx, t, "http://localhost", h.Secret, testRawPayload)
	h.ServeHTTP(w, req)
	testExpectRecorderStatus(t, w, http.StatusOK)
}

func TestHandlerMaxBodySizeExceeded(t *testing.T) {
	ctx := t.Context()
	errorCalled := false
	h := &Handler{
		MaxBodySize: 4,
		Error: func(err error, req *http.Request) {
			errorCalled = true
		},
	}
	w := httptest.NewRecorder()
	req := testNewJSONRequest(ctx, t, "http://localhost", "", testRawPayload)
	h.ServeHTTP(w, req)
	testExpectRecorderStatus(t, w, http.StatusRequestEntityTooLarge)
	assert.True(t, errorCalled)
}

func TestHandlerBodyReadError(t *testing.T) {
	ctx := t.Context()
	h := &Handler{}
	w := httptest.NewRecorder()
	req := testNewJSONRequest(ctx, t, "http://localhost", "", testRawPayload)
	req.Body = testFailingBody{}
	h.ServeHTTP(w, req)
	testExpectRecorderStatus(t, w, http.StatusInternalServerError)
}

type testFailingBody struct{}

func (testFailingBody) Read(p []byte) (int, error) {
	return 0, errors.New("read failed")
}

func (testFailingBody) Close() error {
	return nil
}

func TestRequestError(t *testing.T) {
	err := &RequestError{
		StatusCode: http.StatusTeapot,
		Message:    http.StatusText(http.StatusTeapot),
	}
	_ = err.Error()
}

func testNewJSONRequest(ctx context.Context, t *testing.T, srvURL string, secret string, rawPayload []byte) *http.Request {
	t.Helper()
	req := testNewRequest(ctx, t, srvURL, secret, rawPayload)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(rawPayload))
	return req
}

func testNewRequest(ctx context.Context, t *testing.T, srvURL string, secret string, rawPayload []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srvURL, http.NoBody)
	assert.NoError(t, err)
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", testGetRandomDeliveryID(t))
	if secret != "" {
		testSignRequest(req, secret, rawPayload)
	}
	return req
}

func testSignRequest(req *http.Request, secret string, rawPayload []byte) {
	hash := hmac.New(sha1.New, []byte(secret))
	_, _ = hash.Write(rawPayload)
	mac := hash.Sum(nil)
	signature := hex.EncodeToString(mac)
	signature = "sha1=" + signature
	req.Header.Set("X-Hub-Signature", signature)
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

func testExpectRecorderStatus(t *testing.T, w *httptest.ResponseRecorder, statusCode int) {
	t.Helper()
	assert.Equal(t, statusCode, w.Code)
}
