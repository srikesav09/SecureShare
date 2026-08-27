import { MongoMemoryServer } from "mongodb-memory-server";
import mongoose from "mongoose";

process.env.NODE_ENV = "test";
process.env.PORT = "5001";




let mongoServer;

export const startTestDatabase = async () => {
  mongoServer = await MongoMemoryServer.create();

  const uri = mongoServer.getUri();

  await mongoose.connect(uri);
};

export const clearTestDatabase = async () => {
  const collections = mongoose.connection.collections;

  for (const key of Object.keys(collections)) {
    await collections[key].deleteMany({});
  }
};

export const stopTestDatabase = async () => {
  await mongoose.disconnect();

  if (mongoServer) {
    await mongoServer.stop();
  }
};