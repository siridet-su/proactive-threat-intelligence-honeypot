package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type fakeController struct {
	called    bool
	actionID  string
	sessionID string
	response  controlResponse
	err       error
}

const validActionID = "123e4567-e89b-12d3-a456-426614174000"

func (controller *fakeController) Terminate(_ context.Context, actionID, sessionID string) (controlResponse, error) {
	controller.called = true
	controller.actionID = actionID
	controller.sessionID = sessionID
	return controller.response, controller.err
}

func testServer(controller unixController) *server {
	return &server{tokenHash: sha256.Sum256([]byte("01234567890123456789012345678901")), controller: controller}
}

type responseRecorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header), status: http.StatusOK}
}

func (recorder *responseRecorder) Header() http.Header    { return recorder.header }
func (recorder *responseRecorder) WriteHeader(status int) { recorder.status = status }
func (recorder *responseRecorder) Write(content []byte) (int, error) {
	return recorder.body.Write(content)
}

func newRequest(path string) *http.Request {
	parsed, _ := url.Parse(path)
	return &http.Request{Method: http.MethodPost, URL: parsed, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
}

func decodeResponse(t *testing.T, recorder *responseRecorder) controlResponse {
	t.Helper()
	var response controlResponse
	if err := json.Unmarshal([]byte(recorder.body.String()), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestTerminateSessionRequiresAuthentication(t *testing.T) {
	controller := &fakeController{}
	request := newRequest("/v1/sessions/abcdef123456/terminate")
	request.SetPathValue("sessionID", "abcdef123456")
	recorder := newResponseRecorder()
	testServer(controller).terminateSession(recorder, request)
	if recorder.status != http.StatusUnauthorized || controller.called {
		t.Fatalf("status=%d called=%v", recorder.status, controller.called)
	}
}

func TestTerminateSessionForwardsOnlyValidatedIdentity(t *testing.T) {
	controller := &fakeController{response: controlResponse{OK: true, Status: "terminating"}}
	request := newRequest("/v1/sessions/abcdef123456/terminate")
	request.SetPathValue("sessionID", "abcdef123456")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("X-Action-ID", validActionID)
	recorder := newResponseRecorder()
	testServer(controller).terminateSession(recorder, request)
	if recorder.status != http.StatusAccepted || !controller.called || controller.sessionID != "abcdef123456" || controller.actionID != validActionID {
		t.Fatalf("status=%d controller=%+v response=%+v", recorder.status, controller, decodeResponse(t, recorder))
	}
}

func TestTerminateSessionRejectsInvalidSessionBeforeControl(t *testing.T) {
	controller := &fakeController{}
	request := newRequest("/v1/sessions/not-a-session/terminate")
	request.SetPathValue("sessionID", "not-a-session")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("X-Action-ID", validActionID)
	recorder := newResponseRecorder()
	testServer(controller).terminateSession(recorder, request)
	if recorder.status != http.StatusBadRequest || controller.called {
		t.Fatalf("status=%d called=%v", recorder.status, controller.called)
	}
}
