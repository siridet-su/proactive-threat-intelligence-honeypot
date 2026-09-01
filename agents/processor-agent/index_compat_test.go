package main

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestHasIndexKeysMatchesLegacyNameByKeyPattern(t *testing.T) {
	existing := []existingIndex{{
		Name: "timestamp_-1_autocreated",
		Key:  bson.D{{Key: "timestamp", Value: int32(-1)}},
	}}

	if !hasIndexKeys(existing, bson.D{{Key: "timestamp", Value: -1}}) {
		t.Fatal("expected matching key pattern to reuse legacy index")
	}
}

func TestHasIndexKeysRejectsDifferentKeyPattern(t *testing.T) {
	existing := []existingIndex{{
		Name: "timestamp_-1_autocreated",
		Key:  bson.D{{Key: "timestamp", Value: -1}},
	}}

	if hasIndexKeys(existing, bson.D{{Key: "timestamp", Value: 1}}) {
		t.Fatal("different index ordering must not match")
	}
}
