import "./env.js";

import test from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const servicePath = path.resolve(
  __dirname,
  "../src/services/encryption.service.js"
);

const validKey =
  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

async function importEncryptionService(key) {
  process.env.ENCRYPTION_KEY = key;

  const serviceUrl = pathToFileURL(servicePath).href;

  const moduleUrl =
    `${serviceUrl}?test=${Date.now()}-${Math.random()}`;

  return import(moduleUrl);
}

test("valid 64-character hexadecimal encryption key is accepted", async () => {
  const encryption =
    await importEncryptionService(validKey);

  assert.equal(
    typeof encryption.encryptFile,
    "function"
  );

  assert.equal(
    typeof encryption.decryptBuffer,
    "function"
  );

  assert.equal(
    typeof encryption.generateHash,
    "function"
  );

  assert.equal(
    typeof encryption.generateHashFromBuffer,
    "function"
  );
});

test("short encryption key is rejected", async () => {
  await assert.rejects(
    () => importEncryptionService("1234567890abcdef"),
    {
      message:
        "ENCRYPTION_KEY must be a 64-character hexadecimal string",
    }
  );
});

test("long encryption key is rejected", async () => {
  const invalidKey = "a".repeat(65);

  await assert.rejects(
    () => importEncryptionService(invalidKey),
    {
      message:
        "ENCRYPTION_KEY must be a 64-character hexadecimal string",
    }
  );
});

test("non-hexadecimal encryption key is rejected", async () => {
  const invalidKey =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeg";

  await assert.rejects(
    () => importEncryptionService(invalidKey),
    {
      message:
        "ENCRYPTION_KEY must be a 64-character hexadecimal string",
    }
  );
});

test("empty encryption key is rejected", async () => {
  await assert.rejects(
    () => importEncryptionService(""),
    {
      message: "ENCRYPTION_KEY is not configured",
    }
  );
});

test("missing encryption key is rejected", async () => {
  delete process.env.ENCRYPTION_KEY;

  const serviceUrl = pathToFileURL(servicePath).href;

  const moduleUrl =
    `${serviceUrl}?missing-key=${Date.now()}-${Math.random()}`;

  await assert.rejects(
    () => import(moduleUrl),
    {
      message: "ENCRYPTION_KEY is not configured",
    }
  );
});

test("uppercase hexadecimal encryption key is accepted", async () => {
  const uppercaseKey = validKey.toUpperCase();

  const encryption =
    await importEncryptionService(uppercaseKey);

  assert.equal(
    typeof encryption.encryptFile,
    "function"
  );
});

test("64-character hexadecimal key has exactly 32 bytes", () => {
  const keyBuffer = Buffer.from(
    validKey,
    "hex"
  );

  assert.equal(validKey.length, 64);
  assert.equal(keyBuffer.length, 32);
});