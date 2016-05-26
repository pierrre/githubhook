// Package githubhook provides a HTTP Handler for GitHub webhook.
package githubhook

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

/*
Handler is a HTTP Handler for GitHub webhook.

It supports both JSON and form content types.

Fields (all are optional):
 - Secret is the secret defined in GitHub webhook.
 - DecodePayload is called to decode payload. If it's not defined, JSON unmarshal is used.
 - Delivery is called if a valid delivery is received.
 - Error is called if an error happened.
*/
type Handler struct {
	Secret        string
	DecodePayload func(event string, rawPayload []byte) (interface{}, error)
	Delivery      func(event string, deliveryID string, payload interface{})
	Error         func(err error, req *http.Request)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	err := h.handleRequest(req)
	if err != nil {
		h.handleError(err, w, req)
		return
	}
}

func (h *Handler) handleRequest(req *http.Request) error {
	err := checkHTTPMethod(req)
	if err != nil {
		return err
	}
	event, err := requireHeader("X-GitHub-Event", req)
	if err != nil {
		return err
	}
	deliveryID, err := requireHeader("X-GitHub-Delivery", req)
	if err != nil {
		return err
	}
	rawPayload, err := getRawPayload(req)
	if err != nil {
		return err
	}
	err = h.checkSignature(rawPayload, req)
	if err != nil {
		return err
	}
	payload, err := h.decodePayload(event, rawPayload)
	if err != nil {
		return err
	}
	if h.Delivery != nil {
		h.Delivery(event, deliveryID, payload)
	}
	return nil
}

func checkHTTPMethod(req *http.Request) error {
	if method := req.Method; method != "POST" {
		return &RequestError{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("method not allowed: %s", method),
		}
	}
	return nil
}

func getRawPayload(req *http.Request) ([]byte, error) {
	switch t := req.Header.Get("Content-Type"); t {
	case "application/json":
		return ioutil.ReadAll(req.Body)
	case "application/x-www-form-urlencoded":
		return []byte(req.PostFormValue("payload")), nil
	default:
		return nil, &RequestError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid content type: %s", t),
		}
	}
}

func requireHeader(name string, req *http.Request) (string, error) {
	hd := req.Header.Get(name)
	if hd == "" {
		return "", &RequestError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("missing header: %s", name),
		}
	}
	return hd, nil
}

func (h *Handler) checkSignature(rawPayload []byte, req *http.Request) error {
	if h.Secret == "" {
		return nil
	}
	signature, err := requireHeader("X-Hub-Signature", req)
	if err != nil {
		return err
	}
	err = h.checkSignaturePayload(rawPayload, signature)
	if err != nil {
		return &RequestError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid header X-Hub-Signature: %s", err),
		}
	}
	return nil
}

func (h *Handler) checkSignaturePayload(rawPayload []byte, signature string) error {
	if !strings.HasPrefix(signature, "sha1=") {
		return fmt.Errorf("format")
	}
	signature = strings.TrimPrefix(signature, "sha1=")
	requestMAC, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	hash := hmac.New(sha1.New, []byte(h.Secret))
	_, _ = hash.Write(rawPayload)
	expectedMAC := hash.Sum(nil)
	if !hmac.Equal(requestMAC, expectedMAC) {
		return fmt.Errorf("doesn't match secret")
	}
	return nil
}

func (h *Handler) decodePayload(event string, rawPayload []byte) (interface{}, error) {
	var payload interface{}
	var err error
	if h.DecodePayload != nil {
		payload, err = h.DecodePayload(event, rawPayload)
	} else {
		err = json.Unmarshal(rawPayload, &payload)
	}
	if err != nil {
		return nil, &RequestError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("payload decode error: %s", err),
		}
	}
	return payload, nil
}

func (h *Handler) handleError(err error, w http.ResponseWriter, req *http.Request) {
	var statusCode int
	var message string
	switch err := err.(type) {
	case *RequestError:
		statusCode = err.StatusCode
		message = err.Message
	default:
		statusCode = http.StatusInternalServerError
		message = http.StatusText(statusCode)
	}
	http.Error(w, message, statusCode)
	if h.Error != nil {
		h.Error(err, req)
	}
}

// RequestError represents a request error
type RequestError struct {
	StatusCode int
	Message    string
}

func (err *RequestError) Error() string {
	return fmt.Sprintf("request error %d: %s", err.StatusCode, err.Message)
}
