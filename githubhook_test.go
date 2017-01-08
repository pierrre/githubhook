package githubhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testRawPayload = []byte(`{"foo":"bar"}`)

func TestHandlerJSON(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerForm(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewRequest(t, srv, "", testRawPayload)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form := make(url.Values)
	form.Set("payload", string(testRawPayload))
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerSecret(t *testing.T) {
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, h.Secret, testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
}

func TestHandlerDelivery(t *testing.T) {
	deliveryCalled := false
	h := &Handler{
		Delivery: func(event string, deliveryId string, payload interface{}) {
			deliveryCalled = true
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
	if !deliveryCalled {
		t.Fatal("delivery not called")
	}
}

func TestHandlerDecodePayload(t *testing.T) {
	decodePayloadCalled := false
	h := &Handler{
		DecodePayload: func(event string, rawPayload []byte) (interface{}, error) {
			decodePayloadCalled = true
			return string(rawPayload), nil
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatusOK(t, resp)
	if !decodePayloadCalled {
		t.Fatal("decode payload not called")
	}
}

func TestHandlerError(t *testing.T) {
	errorCalled := false
	h := &Handler{
		Error: func(err error, req *http.Request) {
			errorCalled = true
		},
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusMethodNotAllowed)
	if !errorCalled {
		t.Fatal("error not called")
	}
}

func TestHandlerErrorMethod(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusMethodNotAllowed)
}

func TestHandlerErrorHeaderEvent(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	req.Header.Del("X-GitHub-Event")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderDelivery(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	req.Header.Del("X-GitHub-Delivery")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderContentType(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, "", testRawPayload)
	req.Header.Set("Content-Type", "foobar")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignature(t *testing.T) {
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, h.Secret, testRawPayload)
	req.Header.Del("X-Hub-Signature")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureFormat(t *testing.T) {
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, h.Secret, testRawPayload)
	req.Header.Set("X-Hub-Signature", "foobar")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureHex(t *testing.T) {
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, h.Secret, testRawPayload)
	req.Header.Set("X-Hub-Signature", "sha1=zz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorHeaderSignatureSecret(t *testing.T) {
	h := &Handler{
		Secret: "foobar",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req := testNewJSONRequest(t, srv, h.Secret, testRawPayload)
	testSignRequest(req, "wrong", testRawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorDecodePayload(t *testing.T) {
	h := &Handler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	rawPayload := []byte("not json")
	req := testNewJSONRequest(t, srv, h.Secret, rawPayload)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	testExpectResponseStatus(t, resp, http.StatusBadRequest)
}

func TestHandlerErrorInternal(t *testing.T) {
	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{}
	h.handleError(fmt.Errorf("internal error"), w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected HTTP status code: %d (expected %d)", w.Code, http.StatusInternalServerError)
	}
}

func TestRequestError(t *testing.T) {
	err := &RequestError{
		StatusCode: http.StatusTeapot,
		Message:    http.StatusText(http.StatusTeapot),
	}
	_ = err.Error()
}

func testNewJSONRequest(t *testing.T, srv *httptest.Server, secret string, rawPayload []byte) *http.Request {
	req := testNewRequest(t, srv, secret, rawPayload)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioutil.NopCloser(bytes.NewReader(rawPayload))
	return req
}

func testNewRequest(t *testing.T, srv *httptest.Server, secret string, rawPayload []byte) *http.Request {
	req, err := http.NewRequest("POST", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	signature = fmt.Sprintf("sha1=%s", signature)
	req.Header.Set("X-Hub-Signature", signature)
}

func testGetRandomDeliveryID(t *testing.T) string {
	buf := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func testExpectResponseStatusOK(t *testing.T, resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("unexpected HTTP status code: %d: %s", resp.StatusCode, string(body))
	}
}

func testExpectResponseStatus(t *testing.T, resp *http.Response, statusCode int) {
	if resp.StatusCode != statusCode {
		t.Fatalf("unexpected HTTP status code: %d (expected %d)", resp.StatusCode, statusCode)
	}
}
