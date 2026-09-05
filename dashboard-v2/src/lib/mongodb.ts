import { MongoClient } from 'mongodb';

const options = {};

// API routes are force-dynamic, so MongoDB is a request-time dependency. Keep
// the exported promise shape for existing consumers, but defer URI validation
// and connection creation until the promise is awaited. This lets next build
// collect route metadata without requiring a database secret in CI.
const clientPromise = Promise.resolve().then(() => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('Please add your Mongo URI to .env.local');
  }

  if (process.env.NODE_ENV === 'development') {
    const globalWithMongo = global as typeof globalThis & {
      _mongoClientPromise2?: Promise<MongoClient>;
    };
    if (globalWithMongo._mongoClientPromise2) {
      return globalWithMongo._mongoClientPromise2;
    }

    const client = new MongoClient(uri, options);
    globalWithMongo._mongoClientPromise2 = client.connect();
    return globalWithMongo._mongoClientPromise2;
  }

  const client = new MongoClient(uri, options);
  return client.connect();
});

// Route handlers still receive the rejection when configuration is missing;
// this handler only prevents an unused build-time promise from becoming an
// unhandled-rejection process failure.
clientPromise.catch(() => undefined);

export default clientPromise;
