import "./env.js";

import test, { before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "fs";

import app from "../src/app.js";
import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";
import AuditLog from "../src/models/audit.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase,
} from "./setup.js";

const PASSWORD = "TestPassword123!";

let userCounter = 0;
let testFileCounter = 0;

const createUserAndLogin = async () => {
    const uniqueId =
        `${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}`;

    const email =
        `delete-security-${uniqueId}@example.com`;

    const password = PASSWORD;

    // Use a unique IP for each test account so the
    // application's login rate limiter does not affect
    // unrelated security tests.
    const testIp =
        `10.0.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    // --------------------------------------------------
    // REGISTER
    // --------------------------------------------------

    const registerResponse = await request(app)
        .post("/api/auth/register")
        .set("X-Forwarded-For", testIp)
        .send({
            name: "Delete Security User",
            email,
            password,
        });

    assert.ok(
        [200, 201].includes(registerResponse.statusCode),
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    // --------------------------------------------------
    // GET USER DIRECTLY FROM DATABASE
    // --------------------------------------------------

    const user = await User.findOne({ email });

    assert.ok(
        user,
        `Registered user was not found in database: ${email}`
    );

    assert.ok(
        user._id,
        "Registered user does not have a MongoDB _id"
    );

    // --------------------------------------------------
    // LOGIN
    // --------------------------------------------------

    const loginResponse = await request(app)
        .post("/api/auth/login")
        .set("X-Forwarded-For", testIp)
        .send({
            email,
            password,
        });

    assert.equal(
        loginResponse.statusCode,
        200,
        `Login failed: ${JSON.stringify(loginResponse.body)}`
    );

    // --------------------------------------------------
    // EXTRACT TOKEN
    // --------------------------------------------------

    const token =
        loginResponse.body?.data?.token ||
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.token ||
        loginResponse.body?.accessToken;

    assert.ok(
        token,
        `Login response did not contain an access token: ${JSON.stringify(loginResponse.body)}`
    );

    return {
        token,
        user,
        email,
    };
};

const createFile = async (ownerId, overrides = {}) => {
    assert.ok(
        ownerId,
        "createFile() received an undefined ownerId"
    );

    testFileCounter++;

    return File.create({
        originalName: "test-document.txt",
        storedName:
            `test-document-${Date.now()}-${testFileCounter}.txt`,
        mimeType: "text/plain",
        size: 100,
        s3Key:
            `test-key-${Date.now()}-${testFileCounter}`,
        owner: ownerId,
        iv: "1234567890abcdef1234567890abcdef",
        hash: "a".repeat(64),
        encrypted: true,
        ...overrides,
    });
};

before(async () => {
    await startTestDatabase();
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});


/* =========================================================
   AUTHENTICATION
========================================================= */

test("delete requires authentication", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`);

    assert.equal(response.status, 401);
});


test("delete rejects invalid JWT", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`)
        .set("Authorization", "Bearer invalid.jwt.token");

    assert.equal(response.status, 401);
});


test("delete rejects missing Authorization header", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`);

    assert.equal(response.status, 401);
});


/* =========================================================
   INVALID / NON-EXISTENT FILE
========================================================= */

test("invalid MongoDB file ID is handled safely", async () => {
    const { token } = await createUserAndLogin();

    const response = await request(app)
        .delete("/api/files/not-a-valid-mongodb-id")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 500);
    assert.ok(
        [400, 404].includes(response.status),
        `Unexpected status: ${response.status}`
    );
});


test("non-existent file returns 404", async () => {
    const { token } = await createUserAndLogin();

    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 404);
});


test("already deleted file returns 404", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const firstDelete = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        firstDelete.status,
        200,
        `First delete failed: ${JSON.stringify(firstDelete.body)}`
    );

    const secondDelete = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(secondDelete.status, 404);
});


/* =========================================================
   OWNERSHIP
========================================================= */

test("owner can delete their own file", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.status,
        200,
        `Delete failed: ${JSON.stringify(response.body)}`
    );

    assert.equal(
        response.body.success,
        true
    );
});


test("USER cannot delete another user's file", async () => {
    const owner = await createUserAndLogin();
    const attacker = await createUserAndLogin();

    const file = await createFile(owner.user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${attacker.token}`);

    assert.equal(response.status, 403);

    const fileStillExists = await File.findById(file._id);

    assert.ok(fileStillExists);
});


test("another user cannot delete file by changing request parameters", async () => {
    const owner = await createUserAndLogin();
    const attacker = await createUserAndLogin();

    const file = await createFile(owner.user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${attacker.token}`)
        .send({
            owner: attacker.user._id,
            userId: attacker.user._id,
        });

    assert.equal(response.status, 403);

    const unchangedFile = await File.findById(file._id);

    assert.ok(unchangedFile);

    assert.equal(
        unchangedFile.owner.toString(),
        owner.user._id.toString()
    );
});


/* =========================================================
   DATABASE SECURITY
========================================================= */

test("successful delete removes database record", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    const deletedFile = await File.findById(file._id);

    assert.equal(deletedFile, null);
});


test("failed unauthorized delete does not remove database record", async () => {
    const owner = await createUserAndLogin();
    const attacker = await createUserAndLogin();

    const file = await createFile(owner.user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${attacker.token}`);

    assert.equal(response.status, 403);

    const existingFile = await File.findById(file._id);

    assert.ok(existingFile);
});


/* =========================================================
   RESPONSE SECURITY
========================================================= */

test("delete response does not expose encryption key", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    const responseText =
        JSON.stringify(response.body);

    assert.equal(
        responseText.includes(process.env.ENCRYPTION_KEY),
        false
    );
});


test("delete response does not expose server filesystem path", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    const responseText =
        JSON.stringify(response.body);

    assert.equal(
        responseText.includes(process.cwd()),
        false
    );

    assert.equal(
        responseText.includes("uploads"),
        false
    );
});


test("delete response does not expose S3 key", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const s3Key = file.s3Key;

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    const responseText =
        JSON.stringify(response.body);

    assert.equal(
        responseText.includes(s3Key),
        false
    );
});


/* =========================================================
   AUDIT LOG
========================================================= */

test("successful deletion creates an audit log", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    const auditLog = await AuditLog.findOne({
        resourceId: file._id,
    });

    assert.ok(
        auditLog,
        "Expected an audit log for the deletion"
    );
});


test("unauthorized deletion does not create successful audit log", async () => {
    const owner = await createUserAndLogin();
    const attacker = await createUserAndLogin();

    const file = await createFile(owner.user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${attacker.token}`);

    assert.equal(response.status, 403);

    const auditLogs = await AuditLog.find({
        resourceId: file._id,
        user: attacker.user._id,
    });

    const successfulLogs = auditLogs.filter(
        (log) => log.status === "SUCCESS"
    );

    assert.equal(successfulLogs.length, 0);
});


/* =========================================================
   OWNERSHIP INTEGRITY
========================================================= */

test("file ownership remains unchanged after unauthorized delete attempt", async () => {
    const owner = await createUserAndLogin();
    const attacker = await createUserAndLogin();

    const file = await createFile(owner.user._id);

    await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${attacker.token}`);

    const unchangedFile = await File.findById(file._id);

    assert.ok(unchangedFile);

    assert.equal(
        unchangedFile.owner.toString(),
        owner.user._id.toString()
    );
});


test("one user cannot delete another user's file", async () => {
    const user1 = await createUserAndLogin();
    const user2 = await createUserAndLogin();

    const file1 = await createFile(user1.user._id);
    const file2 = await createFile(user2.user._id);

    const response = await request(app)
        .delete(`/api/files/${file1._id}`)
        .set("Authorization", `Bearer ${user2.token}`);

    assert.equal(response.status, 403);

    assert.ok(await File.findById(file1._id));
    assert.ok(await File.findById(file2._id));
});


/* =========================================================
   PATH / ID MANIPULATION
========================================================= */

test("path traversal cannot be used to delete another file", async () => {
    const { token, user } = await createUserAndLogin();

    const response = await request(app)
        .delete(
            "/api/files/../../etc/passwd"
        )
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 200);
});


test("special characters in file ID do not cause server error", async () => {
    const { token } = await createUserAndLogin();

    const response = await request(app)
        .delete("/api/files/<script>alert(1)</script>")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 500);
});


/* =========================================================
   MULTIPLE FILES
========================================================= */

test("deleting one file does not delete another user's files", async () => {
    const owner = await createUserAndLogin();

    const file1 = await createFile(owner.user._id, {
        originalName: "file-one.txt",
    });

    const file2 = await createFile(owner.user._id, {
        originalName: "file-two.txt",
    });

    const response = await request(app)
        .delete(`/api/files/${file1._id}`)
        .set("Authorization", `Bearer ${owner.token}`);

    assert.equal(response.status, 200);

    assert.equal(
        await File.findById(file1._id),
        null
    );

    assert.ok(
        await File.findById(file2._id)
    );
});


test("deleting multiple files individually works", async () => {
    const { token, user } = await createUserAndLogin();

    const file1 = await createFile(user._id, {
        originalName: "one.txt",
    });

    const file2 = await createFile(user._id, {
        originalName: "two.txt",
    });

    const file3 = await createFile(user._id, {
        originalName: "three.txt",
    });

    for (const file of [file1, file2, file3]) {
        const response = await request(app)
            .delete(`/api/files/${file._id}`)
            .set("Authorization", `Bearer ${token}`);

        assert.equal(response.status, 200);
    }

    assert.equal(
        await File.countDocuments({
            owner: user._id,
        }),
        0
    );
});


/* =========================================================
   HTTP METHOD / ROUTE SECURITY
========================================================= */

test("GET request cannot delete a file", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .get(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 200);

    assert.ok(
        await File.findById(file._id)
    );
});


test("POST request cannot delete a file", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .post(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 200);

    assert.ok(
        await File.findById(file._id)
    );
});


/* =========================================================
   DATA LEAKAGE
========================================================= */

test("successful delete response contains only safe information", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const response = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 200);

    assert.equal(
        response.body.success,
        true
    );

    assert.equal(
        response.body.message,
        "File deleted successfully"
    );

    assert.equal(
        response.body.data,
        undefined
    );
});


test("deleted file ID cannot be used to retrieve the deleted record", async () => {
    const { token, user } = await createUserAndLogin();

    const file = await createFile(user._id);

    const deleteResponse = await request(app)
        .delete(`/api/files/${file._id}`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(deleteResponse.status, 200);

    const fileAfterDeletion =
        await File.findById(file._id);

    assert.equal(
        fileAfterDeletion,
        null
    );
});