import { MongoClient } from 'mongodb';

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error('Please add your Mongo URI to .env.local');
}
const options = {};

let client: MongoClient;
let clientPromise: Promise<MongoClient>;

if (process.env.NODE_ENV === 'development') {
  let globalWithMongo = global as typeof globalThis & {
    _mongoClientPromise2?: Promise<MongoClient>;
  };

  if (!globalWithMongo._mongoClientPromise2) {
    client = new MongoClient(uri, options);
    globalWithMongo._mongoClientPromise2 = client.connect();
  }
  clientPromise = globalWithMongo._mongoClientPromise2;
} else {
  client = new MongoClient(uri, options);
  clientPromise = client.connect();
}

export default clientPromise;
