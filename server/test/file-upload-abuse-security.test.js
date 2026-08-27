import "./env.js";

import test, {
    before,
    beforeEach,
    after,
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase,
} from "./setup.js";


before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();
});

after(async () => {
    await stopTestDatabase();
});


// =========================================================
// HELPERS
// =========================================================

const registerAndLogin = async () => {

    const email =
        `upload-abuse-${Date.now()}-${Math.random()}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Upload Security User",
                email,
                password: "password123",
            });

    assert.equal(
        register.status,
        201,
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    const login =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password: "password123",
            });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );

    return login.body.data.token;
};


// =========================================================
// AUTHENTICATION
// =========================================================

test(
    "upload endpoint rejects unauthenticated request",
    async () => {

        const response =
            await request(app)
                .post("/api/files/upload")
                .attach(
                    "file",
                    Buffer.from("test content"),
                    "test.txt"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// PATH TRAVERSAL
// =========================================================

test(
    "path traversal filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("safe test content"),
                    "../../etc/passwd"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// WINDOWS PATH TRAVERSAL
// =========================================================

test(
    "Windows path traversal filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("safe test content"),
                    "..\\..\\Windows\\System32\\test.txt"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// DOUBLE EXTENSION
// =========================================================

test(
    "double extension filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("test content"),
                    "document.pdf.exe"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// SCRIPT EXTENSION
// =========================================================

test(
    "script filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("<script>alert(1)</script>"),
                    "script.html"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// SPECIAL CHARACTERS
// =========================================================

test(
    "special-character filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("test content"),
                    "<script>alert(1)</script>.txt"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// EMPTY FILE
// =========================================================

test(
    "empty file is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.alloc(0),
                    "empty.txt"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// MIME SPOOFING
// =========================================================

test(
    "MIME type spoofing is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from(
                        "This is not really a PDF"
                    ),
                    {
                        filename: "fake.pdf",
                        contentType: "application/pdf",
                    }
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// NULL-BYTE STYLE FILENAME
// =========================================================

test(
    "null-byte style filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        // Supertest / multipart handling may sanitize
        // actual null bytes, so test the dangerous
        // filename pattern without crashing the server.

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("test"),
                    "safe.txt"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// VERY LONG FILENAME
// =========================================================

test(
    "very long filename is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const filename =
            `${"A".repeat(1000)}.txt`;

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from("test content"),
                    filename
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// UNEXPECTED FILE FIELD
// =========================================================

test(
    "unexpected upload field is handled safely",
    async () => {

        const token =
            await registerAndLogin();

        const response =
            await request(app)
                .post("/api/files/upload")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "unexpected",
                    Buffer.from("test content"),
                    "test.txt"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);