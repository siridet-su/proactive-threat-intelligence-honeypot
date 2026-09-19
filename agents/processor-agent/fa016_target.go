package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const fa016DatabasePrefix = "pti_fa016_test_"

var fa016RunIDPattern = regexp.MustCompile(`^[a-z0-9]+$`)

type fa016MongoTarget struct {
	URI      string
	Database string
	RunID    string
}

// validateFA016MongoTarget is deliberately independent of the Mongo driver.
// Callers must run it before Connect, Database.Drop, or any other callback that
// could touch external state.
func validateFA016MongoTarget(uri, database, runID string) (fa016MongoTarget, error) {
	if uri == "" || database == "" || runID == "" {
		return fa016MongoTarget{}, fmt.Errorf("FA016_MONGO_URI, FA016_MONGO_DB, and FA016_MONGO_RUN_ID are required")
	}
	if !fa016RunIDPattern.MatchString(runID) {
		return fa016MongoTarget{}, fmt.Errorf("invalid FA016_MONGO_RUN_ID")
	}
	wantDB := fa016DatabasePrefix + runID
	if database != wantDB || database == "honeypot_db" {
		return fa016MongoTarget{}, fmt.Errorf("database must be exactly %q", wantDB)
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "mongodb" {
		return fa016MongoTarget{}, fmt.Errorf("FA016_MONGO_URI must use mongodb://")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fa016MongoTarget{}, fmt.Errorf("FA016_MONGO_URI must target loopback")
	}
	pathDB := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if decoded, decodeErr := url.PathUnescape(pathDB); decodeErr != nil || decoded != database {
		return fa016MongoTarget{}, fmt.Errorf("URI database must equal %q", database)
	}
	return fa016MongoTarget{URI: uri, Database: database, RunID: runID}, nil
}

func runWithValidatedFA016Target(uri, database, runID string, connect func(fa016MongoTarget) error) error {
	target, err := validateFA016MongoTarget(uri, database, runID)
	if err != nil {
		return err
	}
	return connect(target)
}
