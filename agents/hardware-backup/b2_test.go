package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestStorageUsageSumsUploadVersionsAcrossPages(t *testing.T) {
	transport := &storageUsageRoundTripper{t: t}

	client := &B2Client{
		httpClient: &http.Client{Transport: transport},
		apiURL:     "https://b2.test",
		authToken:  "test-token",
		bucketID:   "test-bucket",
	}
	usage, err := client.StorageUsage(context.Background())
	if err != nil {
		t.Fatalf("StorageUsage() error = %v", err)
	}
	if usage.StorageBytes != 175 {
		t.Fatalf("StorageBytes = %d, want 175", usage.StorageBytes)
	}
	if usage.FileVersions != 3 {
		t.Fatalf("FileVersions = %d, want 3", usage.FileVersions)
	}
	if transport.calls != 2 {
		t.Fatalf("page calls = %d, want 2", transport.calls)
	}
}

type storageUsageRoundTripper struct {
	t     *testing.T
	calls int
}

func (transport *storageUsageRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path != "/b2api/v2/b2_list_file_versions" {
		transport.t.Errorf("path = %q, want file versions endpoint", request.URL.Path)
	}
	if request.Header.Get("Authorization") != "test-token" {
		transport.t.Errorf("authorization header = %q, want test-token", request.Header.Get("Authorization"))
	}

	var payload struct {
		BucketID      string `json:"bucketId"`
		StartFileName string `json:"startFileName"`
		StartFileID   string `json:"startFileId"`
		MaxFileCount  int    `json:"maxFileCount"`
	}
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		transport.t.Errorf("decode request: %v", err)
	}
	if payload.BucketID != "test-bucket" || payload.MaxFileCount != 1000 {
		transport.t.Errorf("request payload = %+v", payload)
	}

	transport.calls++
	var body []byte
	if transport.calls == 1 {
		body, _ = json.Marshal(b2ListFileVersionsResponse{
			Files: []b2FileVersion{
				{Action: "upload", ContentLength: 100},
				{Action: "hide", ContentLength: 0},
				{Action: "upload", ContentLength: 50},
			},
			NextFileName: "next.jsonl.gz",
			NextFileID:   "version-2",
		})
	} else {
		if payload.StartFileName != "next.jsonl.gz" || payload.StartFileID != "version-2" {
			transport.t.Errorf("pagination payload = %+v", payload)
		}
		body, _ = json.Marshal(b2ListFileVersionsResponse{
			Files: []b2FileVersion{{Action: "upload", ContentLength: 25}},
		})
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    request,
	}, nil
}
