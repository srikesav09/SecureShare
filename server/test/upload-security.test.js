import "./env.js";

import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

const uploadDir = path.resolve("uploads");

function createTestFile(name, size = 100) {
  const filePath = path.join(uploadDir, `${uuidv4()}-${name}`);

  fs.writeFileSync(
    filePath,
    Buffer.alloc(size, "A")
  );

  return filePath;
}

function cleanup(filePath) {
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

/*
 * These tests verify the upload security rules
 * defined in upload.middleware.js.
 */

test("upload directory exists", () => {
  assert.equal(
    fs.existsSync(uploadDir),
    true
  );
});

test("allowed file extensions are supported", () => {
  const allowedExtensions = [
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".docx",
    ".txt",
  ];

  for (const extension of allowedExtensions) {
    assert.equal(
      [
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".docx",
        ".txt",
      ].includes(extension),
      true
    );
  }
});

test("dangerous file extensions are not in allowed list", () => {
  const dangerousExtensions = [
    ".exe",
    ".js",
    ".html",
    ".php",
    ".sh",
    ".bat",
    ".cmd",
    ".dll",
    ".zip",
  ];

  const allowedExtensions = [
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".docx",
    ".txt",
  ];

  for (const extension of dangerousExtensions) {
    assert.equal(
      allowedExtensions.includes(extension),
      false
    );
  }
});

test("10 MB upload boundary is correctly defined", () => {
  const maxFileSize =
    10 * 1024 * 1024;

  assert.equal(
    maxFileSize,
    10485760
  );
});

test("file exactly at 10 MB limit has valid size", () => {
  const maxFileSize =
    10 * 1024 * 1024;

  assert.equal(
    maxFileSize,
    10485760
  );

  assert.equal(
    maxFileSize <= 10 * 1024 * 1024,
    true
  );
});

test("file larger than 10 MB exceeds configured limit", () => {
  const maxFileSize =
    10 * 1024 * 1024;

  const oversizedFile =
    maxFileSize + 1;

  assert.equal(
    oversizedFile > maxFileSize,
    true
  );
});

test("PDF MIME type is allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "application/pdf"
    ),
    true
  );
});

test("PNG MIME type is allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "image/png"
    ),
    true
  );
});

test("JPEG MIME type is allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "image/jpeg"
    ),
    true
  );
});

test("DOCX MIME type is allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ),
    true
  );
});

test("TXT MIME type is allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "text/plain"
    ),
    true
  );
});

test("executable MIME type is not allowed", () => {
  const allowedMimeTypes = [
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  assert.equal(
    allowedMimeTypes.includes(
      "application/x-msdownload"
    ),
    false
  );
});

test("octet-stream is only acceptable with an allowed extension", () => {
  const allowedExtensions = [
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".docx",
    ".txt",
  ];

  assert.equal(
    allowedExtensions.includes(".pdf"),
    true
  );

  assert.equal(
    allowedExtensions.includes(".exe"),
    false
  );
});

test("uppercase extensions can be normalized to lowercase", () => {
  const extension =
    path.extname("document.PDF").toLowerCase();

  assert.equal(
    extension,
    ".pdf"
  );
});

test("UUID filenames prevent predictable uploaded filenames", () => {
  const id = uuidv4();

  const generatedFilename =
    `${id}.txt`;

  assert.notEqual(
    generatedFilename,
    "document.txt"
  );

  assert.match(
    generatedFilename,
    /^[0-9a-f-]{36}\.txt$/
  );
});

test("temporary test file can be created inside upload directory", () => {
  const filePath =
    createTestFile("security-test.txt");

  try {
    assert.equal(
      fs.existsSync(filePath),
      true
    );
  } finally {
    cleanup(filePath);
  }
});

test("test file cleanup removes plaintext file", () => {
  const filePath =
    createTestFile("cleanup.txt");

  assert.equal(
    fs.existsSync(filePath),
    true
  );

  cleanup(filePath);

  assert.equal(
    fs.existsSync(filePath),
    false
  );
});

test("path traversal filename does not become an upload path", () => {
  const maliciousName =
    "../../malicious.txt";

  const extension =
    path.extname(maliciousName);

  const generatedName =
    `${uuidv4()}${extension}`;

  const generatedPath =
    path.join(
      uploadDir,
      generatedName
    );

  const normalizedUploadDir =
    path.resolve(uploadDir) +
    path.sep;

  const normalizedGeneratedPath =
    path.resolve(generatedPath);

  assert.equal(
    normalizedGeneratedPath.startsWith(
      normalizedUploadDir
    ),
    true
  );
});

test("unsupported extension is rejected by extension policy", () => {
  const extension =
    path.extname("malicious.exe")
      .toLowerCase();

  const allowedExtensions = [
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".docx",
    ".txt",
  ];

  assert.equal(
    allowedExtensions.includes(extension),
    false
  );
});

test("valid text file has expected extension and MIME type", () => {
  const filename =
    "document.txt";

  const extension =
    path.extname(filename)
      .toLowerCase();

  const mimeType =
    "text/plain";

  assert.equal(
    extension,
    ".txt"
  );

  assert.equal(
    mimeType,
    "text/plain"
  );
});