import "./env.js";

import assert from "node:assert/strict";
import test, {
    before,
    after,
    beforeEach
} from "node:test";
import fs from "fs";
import path from "path";
import request from "supertest";

import app from "../src/app.js";
import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const PASSWORD = "Password123!";

let token;
let user;
let email;

const uniqueEmail = () =>
    `file-content-${Date.now()}-${Math.random()}@example.com`;

const registerAndLogin = async () => {
    const uniqueId =
        `${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}`;

    const email =
        `file-security-${uniqueId}@example.com`;

    const password = "StrongPassword123!";

    // Give every test account a different client IP.
    // This prevents the production login rate limiter
    // from affecting this security test suite.
    const testIp =
        `10.20.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    // Register
    const registerResponse = await request(app)
        .post("/api/auth/register")
        .set("X-Forwarded-For", testIp)
        .send({
            name: "File Security User",
            email,
            password,
        });

    assert.ok(
        [200, 201].includes(registerResponse.statusCode),
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    // Login
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

    token =
        loginResponse.body?.data?.token ||
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.token ||
        loginResponse.body?.accessToken;

    assert.ok(
        token,
        `Login response did not contain an access token: ${JSON.stringify(loginResponse.body)}`
    );

    // Get the actual MongoDB user instead of relying
    // on the shape of the API response.
    const user = await User.findOne({ email });

    assert.ok(
        user,
        `User was not found after registration: ${email}`
    );

    assert.ok(
        user.id,
        "User does not have a MongoDB _id"
    );

    return {
        token,
        user,
        email,
    };
};

function uploadFile({
    filename,
    content,
    contentType
}) {
    const req =
        request(app)
            .post("/api/files/upload")
            .set(
                "Authorization",
                `Bearer ${token}`
            );

    return req
        .attach(
            "file",
            Buffer.from(content),
            {
                filename,
                contentType
            }
        );
}

before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();
    await registerAndLogin();
});

after(async () => {
    await stopTestDatabase();
});


// ============================================================
// 1. Normal file upload still works
// ============================================================

test(
    "valid text file upload is accepted",
    async () => {
        const response =
            await uploadFile({
                filename: "normal.txt",
                content: "SecureShare test file",
                contentType: "text/plain"
            });

        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );
    }
);


// ============================================================
// 2. Empty file
// ============================================================

test(
    "empty file does not cause server error",
    async () => {
        const response =
            await uploadFile({
                filename: "empty.txt",
                content: "",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 3. Executable extension
// ============================================================

test(
    "executable extension is rejected",
    async () => {
        const response =
            await uploadFile({
                filename: "malware.exe",
                content: "MZ fake executable",
                contentType: "application/octet-stream"
            });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            [400, 415, 422].includes(
                response.status
            ),
            `Unexpected status: ${response.status}`
        );
    }
);


// ============================================================
// 4. Double extension
// ============================================================

test(
    "double executable extension is rejected",
    async () => {
        const response =
            await uploadFile({
                filename: "document.pdf.exe",
                content: "%PDF-1.7 fake executable",
                contentType: "application/pdf"
            });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            [400, 415, 422].includes(
                response.status
            ),
            `Unexpected status: ${response.status}`
        );
    }
);


// ============================================================
// 5. JavaScript disguised as text
// ============================================================

test(
    "script content does not cause server error",
    async () => {
        const response =
            await uploadFile({
                filename: "script.txt",
                content:
                    "<script>alert(document.cookie)</script>",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 6. HTML upload
// ============================================================

test(
    "HTML file is handled safely",
    async () => {
        const response =
            await uploadFile({
                filename: "attack.html",
                content:
                    "<html><script>alert(1)</script></html>",
                contentType: "text/html"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 7. SVG script payload
// ============================================================

test(
    "SVG script payload is handled safely",
    async () => {
        const svg = `
            <svg xmlns="http://www.w3.org/2000/svg">
                <script>alert(document.cookie)</script>
            </svg>
        `;

        const response =
            await uploadFile({
                filename: "image.svg",
                content: svg,
                contentType: "image/svg+xml"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 8. MIME type spoofing
// ============================================================

test(
    "MIME type spoofing does not cause server error",
    async () => {
        const response =
            await uploadFile({
                filename: "fake.pdf",
                content:
                    "This is actually executable-like content",
                contentType: "application/pdf"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 9. PDF signature mismatch
// ============================================================

test(
    "invalid PDF signature is rejected or safely handled",
    async () => {
        const response =
            await uploadFile({
                filename: "fake.pdf",
                content:
                    "NOT A REAL PDF FILE",
                contentType: "application/pdf"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 10. Path traversal filename
// ============================================================

test(
    "path traversal filename cannot escape upload directory",
    async () => {

        const response =
            await uploadFile({
                filename:
                    "../../../../evil.txt",

                content:
                    "path traversal test",

                contentType:
                    "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );

        if (response.status === 201) {

            const body =
                JSON.stringify(
                    response.body
                );

            assert.equal(
                body.includes(
                    "../../../../evil.txt"
                ),
                false
            );

            assert.equal(
                fs.existsSync(
                    path.resolve("evil.txt")
                ),
                false,
                "Uploaded file escaped the uploads directory"
            );

        }
    }
);


// ============================================================
// 11. Null byte filename
// ============================================================

test(
    "null byte filename is safely handled",
    async () => {
        const response =
            await uploadFile({
                filename:
                    "safe.txt\0.exe",
                content:
                    "null byte filename test",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 12. Filename header injection characters
// ============================================================

test(
    "special filename characters are safely handled",
    async () => {
        const response =
            await uploadFile({
                filename:
                    'file"; filename="evil.txt',
                content:
                    "filename injection test",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 13. Very long filename
// ============================================================

test(
    "extremely long filename is handled safely",
    async () => {
        const filename =
            "a".repeat(1000) + ".txt";

        const response =
            await uploadFile({
                filename,
                content:
                    "long filename test",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 14. Unicode filename
// ============================================================

test(
    "Unicode filename is handled safely",
    async () => {
        const response =
            await uploadFile({
                filename:
                    "安全なファイル-தகவல்-📄.txt",
                content:
                    "unicode filename test",
                contentType: "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 15. Filename with directory separators
// ============================================================

test(
    "directory separator filename cannot control storage path",
    async () => {

        const response =
            await uploadFile({
                filename:
                    "folder/../../secret.txt",

                content:
                    "directory traversal test",

                contentType:
                    "text/plain"
            });

        assert.notEqual(
            response.status,
            500
        );

        if (response.status === 201) {

            const body =
                JSON.stringify(
                    response.body
                );

            assert.equal(
                body.includes(
                    "folder/../../secret.txt"
                ),
                false
            );

            assert.equal(
                fs.existsSync(
                    path.resolve("secret.txt")
                ),
                false,
                "Uploaded file escaped the uploads directory"
            );

        }
    }
);