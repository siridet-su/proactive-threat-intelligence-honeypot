package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)
	actionIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type controlRequest struct {
	Action    string `json:"action"`
	ActionID  string `json:"action_id"`
	SessionID string `json:"session_id"`
}

type controlResponse struct {
	OK     bool   `json:"ok"`
	Status string `json:"status"`
}

type unixController interface {
	Ready(context.Context) error
	Terminate(context.Context, string, string) (controlResponse, error)
}

type socketController struct {
	path    string
	timeout time.Duration
}

func (controller socketController) Ready(ctx context.Context) error {
	dialer := net.Dialer{Timeout: controller.timeout}
	connection, err := dialer.DialContext(ctx, "unix", controller.path)
	if err != nil {
		return fmt.Errorf("connect to Cowrie control socket: %w", err)
	}
	return connection.Close()
}

func (controller socketController) Terminate(ctx context.Context, actionID, sessionID string) (controlResponse, error) {
	dialer := net.Dialer{Timeout: controller.timeout}
	connection, err := dialer.DialContext(ctx, "unix", controller.path)
	if err != nil {
		return controlResponse{}, fmt.Errorf("connect to Cowrie control socket: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(controller.timeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return controlResponse{}, fmt.Errorf("set Cowrie control deadline: %w", err)
	}
	request := controlRequest{Action: "terminate_session", ActionID: actionID, SessionID: sessionID}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return controlResponse{}, fmt.Errorf("send Cowrie control request: %w", err)
	}
	var response controlResponse
	reader := bufio.NewReader(io.LimitReader(connection, 2048))
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return controlResponse{}, fmt.Errorf("read Cowrie control response: %w", err)
	}
	return response, nil
}

type server struct {
	tokenHash  [32]byte
	controller unixController
}

func (service *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", service.health)
	mux.HandleFunc("POST /v1/sessions/{sessionID}/terminate", service.terminateSession)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(response, request)
	})
}

func (service *server) health(response http.ResponseWriter, request *http.Request) {
	if !service.authorized(request) {
		writeJSON(response, http.StatusUnauthorized, controlResponse{Status: "unauthorized"})
		return
	}
	if err := service.controller.Ready(request.Context()); err != nil {
		writeJSON(response, http.StatusServiceUnavailable, controlResponse{Status: "control_unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, controlResponse{OK: true, Status: "ready"})
}

func (service *server) authorized(request *http.Request) bool {
	const prefix = "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))))
	return subtle.ConstantTimeCompare(presented[:], service.tokenHash[:]) == 1
}

func writeJSON(response http.ResponseWriter, status int, document controlResponse) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(document)
}

func (service *server) terminateSession(response http.ResponseWriter, request *http.Request) {
	if !service.authorized(request) {
		writeJSON(response, http.StatusUnauthorized, controlResponse{Status: "unauthorized"})
		return
	}
	sessionID := request.PathValue("sessionID")
	actionID := strings.TrimSpace(request.Header.Get("X-Action-ID"))
	if !sessionIDPattern.MatchString(sessionID) || !actionIDPattern.MatchString(actionID) {
		writeJSON(response, http.StatusBadRequest, controlResponse{Status: "invalid_request"})
		return
	}
	var body [1]byte
	read, bodyErr := request.Body.Read(body[:])
	if read != 0 || (bodyErr != nil && !errors.Is(bodyErr, io.EOF)) {
		writeJSON(response, http.StatusBadRequest, controlResponse{Status: "body_not_allowed"})
		return
	}
	result, err := service.controller.Terminate(request.Context(), actionID, sessionID)
	if err != nil {
		log.Printf("action_id=%s session_id=%s outcome=control_unavailable", actionID, sessionID)
		writeJSON(response, http.StatusServiceUnavailable, controlResponse{Status: "control_unavailable"})
		return
	}
	status := http.StatusAccepted
	if result.OK && result.Status != "terminating" {
		result = controlResponse{Status: "control_unavailable"}
		status = http.StatusServiceUnavailable
	} else if !result.OK {
		switch result.Status {
		case "not_found":
			status = http.StatusNotFound
		case "invalid_session", "invalid_request", "unsupported_action":
			status = http.StatusBadRequest
		default:
			status = http.StatusServiceUnavailable
		}
	}
	log.Printf("action_id=%s session_id=%s outcome=%s", actionID, sessionID, result.Status)
	writeJSON(response, status, result)
}

func requiredEnvironment(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s must be set", name)
	}
	return value
}

func privateCredentialFile(path string, mode os.FileMode) bool {
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return false
	}
	permissions := mode.Perm()
	if permissions&0o007 != 0 {
		return false
	}
	if permissions&0o070 == 0 {
		return true
	}
	credentialRoot := filepath.Clean("/run/credentials") + string(os.PathSeparator)
	return permissions == 0o440 && strings.HasPrefix(filepath.Clean(path), credentialRoot)
}

func loadToken(path string) string {
	metadata, err := os.Lstat(path)
	if err != nil {
		log.Fatalf("read response agent credential metadata: %v", err)
	}
	if !privateCredentialFile(path, metadata.Mode()) {
		log.Fatal("response agent credential must be a private regular file")
	}
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		log.Fatalf("read response agent credential: %v", err)
	}
	token := strings.TrimSpace(string(content))
	if len(token) < 32 {
		log.Fatal("response agent credential must contain at least 32 characters")
	}
	return token
}

func main() {
	listenAddress := requiredEnvironment("RESPONSE_AGENT_LISTEN")
	socketPath := requiredEnvironment("COWRIE_CONTROL_SOCKET")
	token := loadToken(requiredEnvironment("RESPONSE_AGENT_TOKEN_FILE"))
	service := &server{
		tokenHash: sha256.Sum256([]byte(token)),
		controller: socketController{
			path:    socketPath,
			timeout: 3 * time.Second,
		},
	}
	httpServer := &http.Server{
		Addr:              listenAddress,
		Handler:           service.routes(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	log.Printf("response agent listening on %s", listenAddress)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
