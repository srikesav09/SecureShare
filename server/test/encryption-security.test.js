import "./env.js";

import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import crypto from "crypto";

import {
  startTestDatabase,
  stopTestDatabase,
} from "./setup.js";

import {
  encryptFile,
  decryptBuffer,
  generateHash,
  generateHashFromBuffer,
} from "../src/services/encryption.service.js";

const TEST_DIR = path.join(process.cwd(), "test", "tmp-encryption");

before(async () => {
  await startTestDatabase();

  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }
});

after(async () => {
  await stopTestDatabase();

  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

function createTestFile(name, content) {
  const filePath = path.join(TEST_DIR, name);

  fs.writeFileSync(filePath, content);

  return filePath;
}


/* =========================================================
   1. BASIC ENCRYPTION / DECRYPTION
   ========================================================= */

test("encrypts and decrypts plaintext correctly", () => {
  const original = Buffer.from(
    "SecureShare confidential test file"
  );

  const filePath = createTestFile(
    "basic.txt",
    original
  );

  const result = encryptFile(filePath);

  assert.ok(result.encryptedPath);
  assert.ok(result.iv);

  assert.equal(result.iv.length, 32);

  assert.ok(fs.existsSync(result.encryptedPath));

  const encryptedData = fs.readFileSync(
    result.encryptedPath
  );

  const decrypted = decryptBuffer(
    encryptedData,
    result.iv
  );

  assert.deepEqual(decrypted, original);

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   2. RANDOM IV
   ========================================================= */

test("each encryption generates a unique IV", () => {
  const content = Buffer.from(
    "Same content should still use different IVs"
  );

  const file1 = createTestFile(
    "iv1.txt",
    content
  );

  const file2 = createTestFile(
    "iv2.txt",
    content
  );

  const result1 = encryptFile(file1);
  const result2 = encryptFile(file2);

  assert.notEqual(
    result1.iv,
    result2.iv
  );

  fs.unlinkSync(result1.encryptedPath);
  fs.unlinkSync(result2.encryptedPath);
});


/* =========================================================
   3. CIPHERTEXT MUST DIFFER FROM PLAINTEXT
   ========================================================= */

test("encrypted content differs from original content", () => {
  const original = Buffer.from(
    "This must not remain readable"
  );

  const filePath = createTestFile(
    "ciphertext.txt",
    original
  );

  const result = encryptFile(filePath);

  const encrypted = fs.readFileSync(
    result.encryptedPath
  );

  assert.notDeepEqual(
    encrypted,
    original
  );

  assert.equal(
    encrypted.toString("utf8").includes(
      "This must not remain readable"
    ),
    false
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   4. HASH DETERMINISTIC
   ========================================================= */

test("same data always produces the same SHA-256 hash", () => {
  const content = Buffer.from(
    "Hash this SecureShare file"
  );

  const filePath = createTestFile(
    "hash.txt",
    content
  );

  const hash1 = generateHash(filePath);
  const hash2 = generateHash(filePath);

  assert.equal(hash1, hash2);

  assert.equal(hash1.length, 64);

  fs.unlinkSync(filePath);
});


/* =========================================================
   5. BUFFER HASH
   ========================================================= */

test("generateHashFromBuffer matches generateHash", () => {
  const content = Buffer.from(
    "Buffer hashing test"
  );

  const filePath = createTestFile(
    "buffer-hash.txt",
    content
  );

  const fileHash = generateHash(filePath);

  const bufferHash =
    generateHashFromBuffer(content);

  assert.equal(
    fileHash,
    bufferHash
  );

  fs.unlinkSync(filePath);
});


/* =========================================================
   6. MODIFIED DATA CHANGES HASH
   ========================================================= */

test("modified data produces a different hash", () => {
  const original = Buffer.from(
    "Original SecureShare data"
  );

  const modified = Buffer.from(
    "Modified SecureShare data"
  );

  const hash1 =
    generateHashFromBuffer(original);

  const hash2 =
    generateHashFromBuffer(modified);

  assert.notEqual(hash1, hash2);
});


/* =========================================================
   7. WRONG IV MUST FAIL
   ========================================================= */

test("wrong IV cannot correctly decrypt encrypted data", () => {
  const original = Buffer.from(
    "Secret information that must remain protected"
  );

  const filePath = createTestFile(
    "wrong-iv.txt",
    original
  );

  const result = encryptFile(filePath);

  const encryptedData = fs.readFileSync(
    result.encryptedPath
  );

  const wrongIv =
    crypto.randomBytes(16).toString("hex");

  let decrypted;

  try {
    decrypted = decryptBuffer(
      encryptedData,
      wrongIv
    );
  } catch {
    // Decryption failure is also acceptable.
    decrypted = null;
  }

  if (decrypted !== null) {
    assert.notDeepEqual(
      decrypted,
      original,
      "Wrong IV must never recover the original plaintext"
    );
  }

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   8. WRONG KEY MUST NOT DECRYPT CORRECTLY
   ========================================================= */

test("wrong encryption key cannot decrypt correctly", () => {
  const original = Buffer.from(
    "Highly confidential information"
  );

  const filePath = createTestFile(
    "wrong-key.txt",
    original
  );

  const result = encryptFile(filePath);

  const encryptedData = fs.readFileSync(
    result.encryptedPath
  );

  const wrongKey = crypto.randomBytes(32);

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    wrongKey,
    Buffer.from(result.iv, "hex")
  );

  assert.throws(() => {
    Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
  });

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   9. BINARY DATA
   ========================================================= */

test("encryption and decryption preserve binary data", () => {
  const binaryData = crypto.randomBytes(4096);

  const filePath = createTestFile(
    "binary.bin",
    binaryData
  );

  const result = encryptFile(filePath);

  const encrypted =
    fs.readFileSync(result.encryptedPath);

  const decrypted = decryptBuffer(
    encrypted,
    result.iv
  );

  assert.deepEqual(
    decrypted,
    binaryData
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   10. EMPTY FILE
   ========================================================= */

test("encryption and decryption handle an empty file", () => {
  const filePath = createTestFile(
    "empty.txt",
    Buffer.alloc(0)
  );

  const result = encryptFile(filePath);

  const encrypted =
    fs.readFileSync(result.encryptedPath);

  const decrypted = decryptBuffer(
    encrypted,
    result.iv
  );

  assert.equal(
    decrypted.length,
    0
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   11. LARGER FILE
   ========================================================= */

test("encryption and decryption preserve larger files", () => {
  const largeData =
    crypto.randomBytes(1024 * 1024);

  const filePath = createTestFile(
    "large.bin",
    largeData
  );

  const result = encryptFile(filePath);

  const encrypted =
    fs.readFileSync(result.encryptedPath);

  const decrypted = decryptBuffer(
    encrypted,
    result.iv
  );

  assert.deepEqual(
    decrypted,
    largeData
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   12. ORIGINAL FILE IS REMOVED
   ========================================================= */

test("original plaintext file is removed after encryption", () => {
  const filePath = createTestFile(
    "removed.txt",
    "Sensitive plaintext"
  );

  const result = encryptFile(filePath);

  assert.equal(
    fs.existsSync(filePath),
    false
  );

  assert.equal(
    fs.existsSync(result.encryptedPath),
    true
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   13. IV FORMAT
   ========================================================= */

test("generated IV is a valid 16-byte hexadecimal value", () => {
  const filePath = createTestFile(
    "iv-format.txt",
    "IV validation"
  );

  const result = encryptFile(filePath);

  assert.match(
    result.iv,
    /^[0-9a-fA-F]{32}$/
  );

  assert.equal(
    Buffer.from(result.iv, "hex").length,
    16
  );

  fs.unlinkSync(result.encryptedPath);
});


/* =========================================================
   14. HASH FORMAT
   ========================================================= */

test("SHA-256 hash is a 64-character hexadecimal string", () => {
  const content = Buffer.from(
    "SHA-256 format test"
  );

  const hash =
    generateHashFromBuffer(content);

  assert.match(
    hash,
    /^[0-9a-fA-F]{64}$/
  );
});


/* =========================================================
   15. SAME PLAINTEXT DOES NOT PRODUCE SAME CIPHERTEXT
   ========================================================= */

test("same plaintext does not produce identical ciphertext", () => {
  const content = Buffer.from(
    "Same secret content"
  );

  const file1 = createTestFile(
    "same1.txt",
    content
  );

  const file2 = createTestFile(
    "same2.txt",
    content
  );

  const result1 = encryptFile(file1);
  const result2 = encryptFile(file2);

  const encrypted1 =
    fs.readFileSync(result1.encryptedPath);

  const encrypted2 =
    fs.readFileSync(result2.encryptedPath);

  assert.notDeepEqual(
    encrypted1,
    encrypted2
  );

  fs.unlinkSync(result1.encryptedPath);
  fs.unlinkSync(result2.encryptedPath);
});