import { MongoClient } from "mongodb";

const options = {
  // Atlas may need more than a few seconds to complete TLS across the current
  // network path. This remains bounded, while avoiding false failures at 5s.
  serverSelectionTimeoutMS: 20_000,
  connectTimeoutMS: 20_000,
};

type MongoGlobal = typeof globalThis & {
  _ptiMongoClientPromise?: Promise<MongoClient>;
};

function createClientPromise(uri: string, globalWithMongo: MongoGlobal) {
  const client = new MongoClient(uri, options);
  const promise = client.connect();

  // Do not keep a rejected connection promise forever after a transient DNS or
  // network failure; the next request can establish a fresh connection.
  promise.catch(() => {
    if (globalWithMongo._ptiMongoClientPromise === promise) {
      delete globalWithMongo._ptiMongoClientPromise;
    }
    void client.close().catch(() => undefined);
  });

  globalWithMongo._ptiMongoClientPromise = promise;
  return promise;
}

export function getMongoClient(): Promise<MongoClient> {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    return Promise.reject(new Error("Please add your Mongo URI to .env.local"));
  }

  const globalWithMongo = global as MongoGlobal;
  return globalWithMongo._ptiMongoClientPromise
    ?? createClientPromise(uri, globalWithMongo);
}
