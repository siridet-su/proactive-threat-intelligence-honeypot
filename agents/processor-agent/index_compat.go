package main

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type existingIndex struct {
	Name string `bson:"name"`
	Key  bson.D `bson:"key"`
}

// ensureIndexModels creates only key patterns that do not already exist.
// MongoDB treats an index with the same keys and a different name as a
// conflict, even when the existing index is fully usable by the query plan.
func ensureIndexModels(ctx context.Context, collection *mongo.Collection, wanted []mongo.IndexModel) error {
	cursor, err := collection.Indexes().List(ctx)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var existing []existingIndex
	for cursor.Next(ctx) {
		var index existingIndex
		if err := cursor.Decode(&index); err != nil {
			return err
		}
		existing = append(existing, index)
	}
	if err := cursor.Err(); err != nil {
		return err
	}

	for _, model := range wanted {
		keys, ok := model.Keys.(bson.D)
		if !ok {
			return fmt.Errorf("unsupported index key type %T", model.Keys)
		}
		if hasIndexKeys(existing, keys) {
			continue
		}
		if _, err := collection.Indexes().CreateOne(ctx, model); err != nil {
			return err
		}
	}
	return nil
}

func hasIndexKeys(existing []existingIndex, wanted bson.D) bool {
	for _, index := range existing {
		if sameIndexKeys(index.Key, wanted) {
			return true
		}
	}
	return false
}

func sameIndexKeys(left, right bson.D) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Key != right[i].Key || fmt.Sprint(left[i].Value) != fmt.Sprint(right[i].Value) {
			return false
		}
	}
	return true
}
