package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	b2NativeAPIVersion = "v4"
	b2AuthorizeURL     = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account"
)

const (
	b2RequestAttempts = 4
	b2RetryBaseDelay  = time.Second
)

type B2Client struct {
	httpClient *http.Client
	apiURL     string
	authToken  string
	bucketID   string
	bucketName string
}

type b2AuthorizationResponse struct {
	AccountID          string `json:"accountId"`
	AuthorizationToken string `json:"authorizationToken"`
	APIInfo            struct {
		StorageAPI struct {
			APIURL  string `json:"apiUrl"`
			Allowed struct {
				Buckets    []b2AllowedBucket `json:"buckets"`
				NamePrefix string            `json:"namePrefix"`
			} `json:"allowed"`
		} `json:"storageApi"`
	} `json:"apiInfo"`
	// These fields keep the decoder compatible with older authorization
	// responses while new application keys use the v4 response shape above.
	APIURL  string `json:"apiUrl"`
	Allowed struct {
		BucketID   string `json:"bucketId"`
		BucketName string `json:"bucketName"`
		NamePrefix string `json:"namePrefix"`
	} `json:"allowed"`
}

type b2AllowedBucket struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type b2Bucket struct {
	BucketID   string `json:"bucketId"`
	BucketName string `json:"bucketName"`
}

type b2ListBucketsResponse struct {
	Buckets []b2Bucket `json:"buckets"`
}

type b2UploadURLResponse struct {
	AuthorizationToken string `json:"authorizationToken"`
	UploadURL          string `json:"uploadUrl"`
}

type b2UploadResponse struct {
	FileID      string `json:"fileId"`
	FileName    string `json:"fileName"`
	ContentSha1 string `json:"contentSha1"`
	ContentType string `json:"contentType"`
	ContentSize int64  `json:"contentLength"`
}

type b2FileVersion struct {
	Action        string `json:"action"`
	ContentLength int64  `json:"contentLength"`
}

type b2ListFileVersionsResponse struct {
	Files        []b2FileVersion `json:"files"`
	NextFileName string          `json:"nextFileName"`
	NextFileID   string          `json:"nextFileId"`
}

type b2StorageUsage struct {
	StorageBytes int64
	FileVersions int64
}

func NewB2Client(ctx context.Context, cfg Config) (*B2Client, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	authorization, err := authorizeB2(ctx, client, cfg.B2KeyID, cfg.B2ApplicationKey)
	if err != nil {
		return nil, err
	}

	apiURL := authorization.storageAPIURL()
	if apiURL == "" {
		return nil, fmt.Errorf("B2 authorization response is missing storage API URL")
	}
	bucketID, err := authorization.bucketIDFor(cfg.B2Bucket)
	if err != nil {
		return nil, err
	}
	if bucketID == "" {
		bucketID, err = findB2Bucket(ctx, client, apiURL, authorization.AccountID, authorization.AuthorizationToken, cfg.B2Bucket)
		if err != nil {
			return nil, err
		}
	}
	if prefix := authorization.allowedNamePrefix(); prefix != "" {
		for _, target := range cfg.Targets {
			targetPrefix := strings.TrimSuffix(target.Prefix, "/") + "/"
			if !strings.HasPrefix(targetPrefix, prefix) {
				return nil, fmt.Errorf("B2 key prefix %q does not allow backup target %q", prefix, target.ID)
			}
		}
	}

	return &B2Client{
		httpClient: client,
		apiURL:     strings.TrimRight(apiURL, "/"),
		authToken:  authorization.AuthorizationToken,
		bucketID:   bucketID,
		bucketName: cfg.B2Bucket,
	}, nil
}

func (authorization b2AuthorizationResponse) storageAPIURL() string {
	if authorization.APIInfo.StorageAPI.APIURL != "" {
		return authorization.APIInfo.StorageAPI.APIURL
	}
	return authorization.APIURL
}

func (authorization b2AuthorizationResponse) bucketIDFor(bucketName string) (string, error) {
	allowedBuckets := authorization.APIInfo.StorageAPI.Allowed.Buckets
	if len(allowedBuckets) > 0 {
		for _, bucket := range allowedBuckets {
			if bucket.Name == bucketName {
				return bucket.ID, nil
			}
		}
		if len(allowedBuckets) == 1 && allowedBuckets[0].Name == "" {
			return allowedBuckets[0].ID, nil
		}
		return "", fmt.Errorf("B2 key is not authorized for bucket %q", bucketName)
	}

	if authorization.Allowed.BucketName != "" && authorization.Allowed.BucketName != bucketName {
		return "", fmt.Errorf("B2 key is restricted to bucket %q, expected %q", authorization.Allowed.BucketName, bucketName)
	}
	return authorization.Allowed.BucketID, nil
}

func (authorization b2AuthorizationResponse) allowedNamePrefix() string {
	if prefix := strings.TrimSpace(authorization.APIInfo.StorageAPI.Allowed.NamePrefix); prefix != "" {
		return prefix
	}
	return strings.TrimSpace(authorization.Allowed.NamePrefix)
}

func authorizeB2(ctx context.Context, client *http.Client, keyID, applicationKey string) (b2AuthorizationResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, b2AuthorizeURL, nil)
	if err != nil {
		return b2AuthorizationResponse{}, fmt.Errorf("create B2 authorization request: %w", err)
	}
	request.SetBasicAuth(keyID, applicationKey)
	response, err := client.Do(request)
	if err != nil {
		return b2AuthorizationResponse{}, fmt.Errorf("authorize B2: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return b2AuthorizationResponse{}, b2HTTPError("authorize B2", response)
	}

	var authorization b2AuthorizationResponse
	if err := json.NewDecoder(response.Body).Decode(&authorization); err != nil {
		return b2AuthorizationResponse{}, fmt.Errorf("decode B2 authorization response: %w", err)
	}
	if authorization.storageAPIURL() == "" || authorization.AuthorizationToken == "" {
		return b2AuthorizationResponse{}, fmt.Errorf("B2 authorization response is missing API URL or token")
	}
	return authorization, nil
}

func findB2Bucket(ctx context.Context, client *http.Client, apiURL, accountID, authToken, bucketName string) (string, error) {
	payload, err := json.Marshal(struct {
		AccountID  string `json:"accountId"`
		BucketName string `json:"bucketName"`
	}{
		AccountID:  accountID,
		BucketName: bucketName,
	})
	if err != nil {
		return "", fmt.Errorf("encode B2 bucket request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiURL, "/")+"/b2api/"+b2NativeAPIVersion+"/b2_list_buckets", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create B2 bucket request: %w", err)
	}
	request.Header.Set("Authorization", authToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("list B2 buckets: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", b2HTTPError("list B2 buckets", response)
	}
	var listed b2ListBucketsResponse
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil {
		return "", fmt.Errorf("decode B2 bucket response: %w", err)
	}
	for _, bucket := range listed.Buckets {
		if bucket.BucketName == bucketName {
			return bucket.BucketID, nil
		}
	}
	return "", fmt.Errorf("B2 bucket %q was not found", bucketName)
}

func (client *B2Client) Upload(ctx context.Context, path, objectName, contentType, sha1Hex string, size int64) (b2UploadResponse, error) {
	uploadURL, authorizationToken, err := client.getUploadURL(ctx)
	if err != nil {
		return b2UploadResponse{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return b2UploadResponse{}, fmt.Errorf("open archive for B2 upload: %w", err)
	}
	defer file.Close()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, file)
	if err != nil {
		return b2UploadResponse{}, fmt.Errorf("create B2 upload request: %w", err)
	}
	request.Header.Set("Authorization", authorizationToken)
	request.Header.Set("X-Bz-File-Name", url.QueryEscape(objectName))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Content-Length", fmt.Sprintf("%d", size))
	request.Header.Set("X-Bz-Content-Sha1", sha1Hex)
	request.ContentLength = size
	response, err := client.httpClient.Do(request)
	if err != nil {
		return b2UploadResponse{}, fmt.Errorf("upload %s to B2: %w", objectName, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return b2UploadResponse{}, b2HTTPError("upload B2 archive", response)
	}
	var uploaded b2UploadResponse
	if err := json.NewDecoder(response.Body).Decode(&uploaded); err != nil {
		return b2UploadResponse{}, fmt.Errorf("decode B2 upload response: %w", err)
	}
	if uploaded.FileName == "" || uploaded.ContentSha1 != sha1Hex {
		return b2UploadResponse{}, fmt.Errorf("B2 upload response failed integrity check")
	}
	return uploaded, nil
}

func (client *B2Client) StorageUsage(ctx context.Context, prefix string) (b2StorageUsage, error) {
	usage := b2StorageUsage{}
	startFileName := ""
	startFileID := ""

	for {
		page, err := client.listFileVersions(ctx, startFileName, startFileID, prefix)
		if err != nil {
			return b2StorageUsage{}, err
		}
		for _, file := range page.Files {
			if file.Action != "upload" {
				continue
			}
			if file.ContentLength < 0 {
				return b2StorageUsage{}, fmt.Errorf("B2 returned a negative file size")
			}
			usage.StorageBytes += file.ContentLength
			usage.FileVersions++
		}

		if page.NextFileName == "" && page.NextFileID == "" {
			return usage, nil
		}
		if page.NextFileName == startFileName && page.NextFileID == startFileID {
			return b2StorageUsage{}, fmt.Errorf("B2 file version pagination did not advance")
		}
		startFileName = page.NextFileName
		startFileID = page.NextFileID
	}
}

func (client *B2Client) listFileVersions(ctx context.Context, startFileName, startFileID, prefix string) (b2ListFileVersionsResponse, error) {
	payload, err := json.Marshal(struct {
		BucketID      string `json:"bucketId"`
		StartFileName string `json:"startFileName,omitempty"`
		StartFileID   string `json:"startFileId,omitempty"`
		MaxFileCount  int    `json:"maxFileCount"`
		Prefix        string `json:"prefix,omitempty"`
	}{
		BucketID:      client.bucketID,
		StartFileName: startFileName,
		StartFileID:   startFileID,
		MaxFileCount:  1000,
		Prefix:        prefix,
	})
	if err != nil {
		return b2ListFileVersionsResponse{}, fmt.Errorf("encode B2 storage usage request: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= b2RequestAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.apiURL+"/b2api/"+b2NativeAPIVersion+"/b2_list_file_versions", bytes.NewReader(payload))
		if err != nil {
			return b2ListFileVersionsResponse{}, fmt.Errorf("create B2 storage usage request: %w", err)
		}
		request.Header.Set("Authorization", client.authToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.httpClient.Do(request)
		if err != nil {
			lastErr = fmt.Errorf("list B2 file versions: %w", err)
		} else if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			lastErr = b2HTTPError("list B2 file versions", response)
			_ = response.Body.Close()
			if !retryableB2Status(response.StatusCode) {
				return b2ListFileVersionsResponse{}, lastErr
			}
		} else {
			var page b2ListFileVersionsResponse
			decodeErr := json.NewDecoder(response.Body).Decode(&page)
			_ = response.Body.Close()
			if decodeErr != nil {
				lastErr = fmt.Errorf("decode B2 storage usage response: %w", decodeErr)
			} else {
				return page, nil
			}
		}

		if attempt == b2RequestAttempts {
			return b2ListFileVersionsResponse{}, lastErr
		}
		if err := waitForB2Retry(ctx, attempt); err != nil {
			return b2ListFileVersionsResponse{}, err
		}
	}
	return b2ListFileVersionsResponse{}, lastErr
}

func (client *B2Client) getUploadURL(ctx context.Context) (string, string, error) {
	payload, err := json.Marshal(struct {
		BucketID string `json:"bucketId"`
	}{BucketID: client.bucketID})
	if err != nil {
		return "", "", fmt.Errorf("encode B2 upload URL request: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= b2RequestAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.apiURL+"/b2api/"+b2NativeAPIVersion+"/b2_get_upload_url", bytes.NewReader(payload))
		if err != nil {
			return "", "", fmt.Errorf("create B2 upload URL request: %w", err)
		}
		request.Header.Set("Authorization", client.authToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.httpClient.Do(request)
		if err != nil {
			lastErr = fmt.Errorf("get B2 upload URL: %w", err)
		} else if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			lastErr = b2HTTPError("get B2 upload URL", response)
			_ = response.Body.Close()
			if !retryableB2Status(response.StatusCode) {
				return "", "", lastErr
			}
		} else {
			var uploadURL b2UploadURLResponse
			decodeErr := json.NewDecoder(response.Body).Decode(&uploadURL)
			_ = response.Body.Close()
			if decodeErr != nil {
				lastErr = fmt.Errorf("decode B2 upload URL response: %w", decodeErr)
			} else if uploadURL.UploadURL == "" || uploadURL.AuthorizationToken == "" {
				lastErr = fmt.Errorf("B2 upload URL response is incomplete")
			} else {
				return uploadURL.UploadURL, uploadURL.AuthorizationToken, nil
			}
		}

		if attempt == b2RequestAttempts {
			return "", "", lastErr
		}
		if err := waitForB2Retry(ctx, attempt); err != nil {
			return "", "", err
		}
	}
	return "", "", lastErr
}

func retryableB2Status(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func waitForB2Retry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt) * b2RetryBaseDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func b2HTTPError(operation string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	return fmt.Errorf("%s: %s: %s", operation, response.Status, strings.TrimSpace(string(body)))
}
