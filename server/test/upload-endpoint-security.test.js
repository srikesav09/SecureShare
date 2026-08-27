import "./env.js";

import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "fs";
import path from "path";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";

import {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} from "./setup.js";

const TEST_UPLOAD_DIR = path.resolve("uploads");

let token;

const validPdf = Buffer.from(
  "%PDF-1.7\nValid PDF test content"
);

const validPng = Buffer.from([
  0x89,
  0x50,
  0x4e,
  0x47,
  0x0d,
  0x0a,
  0x1a,
  0x0a,
  0x00,
  0x00,
]);

const validJpg = Buffer.from([
  0xff,
  0xd8,
  0xff,
  0xe0,
  0x00,
  0x10,
  0x4a,
  0x46,
  0x49,
  0x46,
]);

const validTxt = Buffer.from(
  "This is a valid UTF-8 text file."
);


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {
  await startTestDatabase();

  if (!fs.existsSync(TEST_UPLOAD_DIR)) {
    fs.mkdirSync(TEST_UPLOAD_DIR, {
      recursive: true,
    });
  }

  /*
   * Create ONE user only.
   *
   * We intentionally do not register/login before
   * every test because the production registration/login
   * rate limiter must remain unchanged.
   */

  const email = "upload-security-test@example.com";

  const registerResponse = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Upload Security User",
      email,
      password: "Password123!",
    });

  assert.equal(
    registerResponse.status,
    201,
    `Registration failed: ${JSON.stringify(registerResponse.body)}`
  );

  const loginResponse = await request(app)
    .post("/api/auth/login")
    .send({
      email,
      password: "Password123!",
    });

  assert.equal(
    loginResponse.status,
    200,
    `Login failed: ${JSON.stringify(loginResponse.body)}`
  );

  token =
    loginResponse.body.data?.token ||
    loginResponse.body.token;

  assert.ok(
    token,
    "Login response did not contain an access token"
  );
});


after(async () => {
  await stopTestDatabase();

  if (fs.existsSync(TEST_UPLOAD_DIR)) {
    const files = fs.readdirSync(TEST_UPLOAD_DIR);

    for (const file of files) {
      try {
        fs.unlinkSync(
          path.join(TEST_UPLOAD_DIR, file)
        );
      } catch {}
    }
  }
});


/* =========================================================
   AUTHENTICATION
   ========================================================= */

test("upload requires authentication", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .attach("file", validPdf, {
      filename: "test.pdf",
      contentType: "application/pdf",
    });

  assert.equal(response.status, 401);
});


/* =========================================================
   VALID FILE TYPES
   ========================================================= */

test("accepts a valid PDF upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach("file", validPdf, {
      filename: "document.pdf",
      contentType: "application/pdf",
    });

  assert.equal(
    response.status,
    201,
    JSON.stringify(response.body)
  );
});


test("accepts a valid PNG upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach("file", validPng, {
      filename: "image.png",
      contentType: "image/png",
    });

  assert.equal(response.status, 201);
});


test("accepts a valid JPEG upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach("file", validJpg, {
      filename: "image.jpg",
      contentType: "image/jpeg",
    });

  assert.equal(response.status, 201);
});


test("accepts a valid TXT upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach("file", validTxt, {
      filename: "notes.txt",
      contentType: "text/plain",
    });

  assert.equal(response.status, 201);
});


/* =========================================================
   EXTENSION VALIDATION
   ========================================================= */

test("rejects unsupported file extension", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("malicious executable content"),
      {
        filename: "malware.exe",
        contentType: "application/octet-stream",
      }
    );

  assert.equal(response.status, 400);
});


test("rejects JavaScript file upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("console.log('malicious');"),
      {
        filename: "script.js",
        contentType: "application/javascript",
      }
    );

  assert.equal(response.status, 400);
});


test("rejects HTML file upload", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("<script>alert(1)</script>"),
      {
        filename: "attack.html",
        contentType: "text/html",
      }
    );

  assert.equal(response.status, 400);
});


/* =========================================================
   MIME TYPE VALIDATION
   ========================================================= */

test("rejects unsupported MIME type", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validPdf,
      {
        filename: "document.pdf",
        contentType: "application/javascript",
      }
    );

  assert.equal(response.status, 400);
});


/* =========================================================
   FILE SIGNATURE VALIDATION
   ========================================================= */

test("rejects PDF extension with invalid PDF signature", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("This is NOT a PDF"),
      {
        filename: "fake.pdf",
        contentType: "application/pdf",
      }
    );

  assert.equal(response.status, 400);
});


test("rejects PNG extension with invalid PNG signature", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("This is not a PNG"),
      {
        filename: "fake.png",
        contentType: "image/png",
      }
    );

  assert.equal(response.status, 400);
});


test("rejects JPEG extension with invalid JPEG signature", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      Buffer.from("This is not a JPEG"),
      {
        filename: "fake.jpg",
        contentType: "image/jpeg",
      }
    );

  assert.equal(response.status, 400);
});


test("rejects file when extension and content do not match", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validPng,
      {
        filename: "fake.pdf",
        contentType: "application/pdf",
      }
    );

  assert.equal(response.status, 400);
});


/* =========================================================
   MISSING FILE
   ========================================================= */

test("rejects request without a file", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .send({});

  assert.notEqual(response.status, 201);
});


/* =========================================================
   PATH TRAVERSAL
   ========================================================= */

test("does not allow path traversal through filename", async () => {
  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validPdf,
      {
        filename: "../../malicious.pdf",
        contentType: "application/pdf",
      }
    );

  assert.equal(response.status, 201);

  assert.equal(
    fs.existsSync(
      path.resolve("malicious.pdf")
    ),
    false,
    "Uploaded file escaped the uploads directory"
  );
});


/* =========================================================
   RANDOM STORAGE NAME
   ========================================================= */

test("uploaded file does not expose the original filename in local storage", async () => {
  const originalName = "my-secret-document.pdf";

  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach("file", validPdf, {
      filename: originalName,
      contentType: "application/pdf",
    });

  assert.equal(
    response.status,
    201,
    JSON.stringify(response.body)
  );

  /*
   * SecureShare may encrypt/upload the file and remove
   * the temporary local plaintext/encrypted file.
   *
   * Therefore an empty uploads directory is valid.
   *
   * The security property we actually care about is that
   * the original filename is NOT used as a local storage
   * filename.
   */

  const files = fs.existsSync(TEST_UPLOAD_DIR)
    ? fs.readdirSync(TEST_UPLOAD_DIR)
    : [];

  assert.equal(
    files.includes(originalName),
    false,
    "Original filename was exposed in local storage"
  );
});

/* =========================================================
   DATABASE RECORD
   ========================================================= */

test("successful upload creates a database record", async () => {
  const beforeCount =
    await File.countDocuments();

  const response = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validPdf,
      {
        filename: "database-test.pdf",
        contentType: "application/pdf",
      }
    );

  assert.equal(response.status, 201);

  const afterCount =
    await File.countDocuments();

  assert.equal(
    afterCount,
    beforeCount + 1
  );
});


/* =========================================================
   MULTIPLE UPLOADS
   ========================================================= */

test("multiple valid uploads are accepted", async () => {
  const first = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validPdf,
      {
        filename: "one.pdf",
        contentType: "application/pdf",
      }
    );

  const second = await request(app)
    .post("/api/files/upload")
    .set("Authorization", `Bearer ${token}`)
    .attach(
      "file",
      validTxt,
      {
        filename: "two.txt",
        contentType: "text/plain",
      }
    );

  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
});


/* =========================================================
   MALICIOUS CONTENT
   ========================================================= */

test("malicious content cannot bypass signature validation", async () => {
  const malicious = Buffer.from(
    "<script>alert(document.cookie)</script>"
  );

  const extensions = [
    [".pdf", "application/pdf"],
    [".png", "image/png"],
    [".jpg", "image/jpeg"],
  ];

  for (const [extension, mimeType] of extensions) {
    const response = await request(app)
      .post("/api/files/upload")
      .set("Authorization", `Bearer ${token}`)
      .attach(
        "file",
        malicious,
        {
          filename: `malicious${extension}`,
          contentType: mimeType,
        }
      );

    assert.equal(
      response.status,
      400,
      `Malicious content bypassed validation for ${extension}`
    );
  }
});