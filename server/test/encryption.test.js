import "./env.js";

import "../test/setup.js";

import test from "node:test";
import assert from "node:assert";
import fs from "fs";
import os from "os";
import path from "path";

import {
  encryptFile,
  decryptBuffer,
  generateHash,
  generateHashFromBuffer
} from "../src/services/encryption.service.js";

test("encrypts and decrypts a file correctly", () => {
  const tempDir = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "secureshare-test-"
    )
  );

  const filePath =
    path.join(tempDir, "test.txt");

  const originalData =
    Buffer.from(
      "SecureShare encryption test"
    );

  fs.writeFileSync(
    filePath,
    originalData
  );

  const result =
    encryptFile(filePath);

  assert.ok(
    result.encryptedPath
  );

  assert.ok(result.iv);

  assert.ok(
    fs.existsSync(
      result.encryptedPath
    )
  );

  const encryptedData =
    fs.readFileSync(
      result.encryptedPath
    );

  const decrypted =
    decryptBuffer(
      encryptedData,
      result.iv
    );

  assert.deepStrictEqual(
    decrypted,
    originalData
  );

  fs.rmSync(
    tempDir,
    {
      recursive: true,
      force: true
    }
  );
});

test("encryption produces different IVs", () => {
  const tempDir = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "secureshare-test-"
    )
  );

  const file1 =
    path.join(tempDir, "one.txt");

  const file2 =
    path.join(tempDir, "two.txt");

  fs.writeFileSync(
    file1,
    "same content"
  );

  fs.writeFileSync(
    file2,
    "same content"
  );

  const result1 =
    encryptFile(file1);

  const result2 =
    encryptFile(file2);

  assert.notStrictEqual(
    result1.iv,
    result2.iv
  );

  fs.rmSync(
    tempDir,
    {
      recursive: true,
      force: true
    }
  );
});

test("encrypted content differs from original", () => {
  const tempDir = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "secureshare-test-"
    )
  );

  const filePath =
    path.join(
      tempDir,
      "test.txt"
    );

  const original =
    Buffer.from("secret data");

  fs.writeFileSync(
    filePath,
    original
  );

  const result =
    encryptFile(filePath);

  const encrypted =
    fs.readFileSync(
      result.encryptedPath
    );

  assert.notDeepStrictEqual(
    encrypted,
    original
  );

  fs.rmSync(
    tempDir,
    {
      recursive: true,
      force: true
    }
  );
});

test("hash is deterministic", () => {
  const tempDir = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "secureshare-test-"
    )
  );

  const filePath =
    path.join(
      tempDir,
      "test.txt"
    );

  fs.writeFileSync(
    filePath,
    "hash test"
  );

  const hash1 =
    generateHash(filePath);

  const buffer =
    fs.readFileSync(filePath);

  const hash2 =
    generateHashFromBuffer(buffer);

  assert.strictEqual(
    hash1,
    hash2
  );

  assert.strictEqual(
    hash1.length,
    64
  );

  fs.rmSync(
    tempDir,
    {
      recursive: true,
      force: true
    }
  );
});

test("modified data produces different hash", () => {
  const original =
    Buffer.from("original");

  const modified =
    Buffer.from("modified");

  const hash1 =
    generateHashFromBuffer(
      original
    );

  const hash2 =
    generateHashFromBuffer(
      modified
    );

  assert.notStrictEqual(
    hash1,
    hash2
  );
});