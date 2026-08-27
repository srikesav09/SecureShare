import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
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

const createUserAndLogin = async () => {
    const email =
        `download-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const password = "password123";

    // Give every test login a different client IP so that
    // the production login rate limiter does not interfere
    // with this security test suite.
    const testIp =
        `10.40.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    const registerResponse =
        await request(app)
            .post("/api/auth/register")
            .set("X-Forwarded-For", testIp)
            .send({
                name: "Download Security User",
                email,
                password
            });

    assert.ok(
        [200, 201].includes(registerResponse.status),
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    const loginResponse =
        await request(app)
            .post("/api/auth/login")
            .set("X-Forwarded-For", testIp)
            .send({
                email,
                password
            });

    assert.equal(
        loginResponse.status,
        200,
        `Login failed: ${JSON.stringify(loginResponse.body)}`
    );

    const token =
        loginResponse.body?.data?.token ||
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.token ||
        loginResponse.body?.accessToken;

    assert.ok(
        token,
        `Login response did not contain an access token: ${JSON.stringify(loginResponse.body)}`
    );

    const user =
        loginResponse.body?.data?.user ||
        loginResponse.body?.user ||
        await User.findOne({ email });

    assert.ok(
        user,
        `User was not found after login: ${email}`
    );

    return {
        token,
        user,
        email
    };
};


const createFile = async (ownerId, overrides = {}) => {

    assert.ok(ownerId);

    return await File.create({
        owner: ownerId,

        originalName:
            overrides.originalName ||
            "download-test.txt",

        storedName:
            overrides.storedName ||
            `download-${Date.now()}-${Math.random()}.txt`,

        s3Key:
            overrides.s3Key ||
            `test/download-${Date.now()}-${Math.random()}.txt`,

        mimeType:
            overrides.mimeType ||
            "text/plain",

        size:
            overrides.size ||
            100,

        ...overrides
    });
};


// =========================================================
// AUTHENTICATION
// =========================================================

test(
    "file download rejects unauthenticated request",
    async () => {

        const { user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response =
            await request(app)
                .get(
                    `/api/files/${file._id}/download`
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// INVALID FILE ID
// =========================================================

test(
    "file download safely rejects invalid MongoDB ID",
    async () => {

        const { token } =
            await createUserAndLogin();

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-valid-id/download"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// NON-EXISTENT FILE
// =========================================================

test(
    "file download rejects non-existent file",
    async () => {

        const { token } =
            await createUserAndLogin();

        const mongoose =
            await import("mongoose");

        const fakeId =
            new mongoose.Types.ObjectId();

        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            [404, 400].includes(response.status)
        );
    }
);


// =========================================================
// USER ISOLATION
// =========================================================

test(
    "user cannot download another user's file",
    async () => {

        const owner =
            await createUserAndLogin();

        const attacker =
            await createUserAndLogin();

        const file =
            await createFile(owner.user.id);

        const response =
            await request(app)
                .get(
                    `/api/files/${file._id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${attacker.token}`
                );

        assert.ok(
            [401, 403, 404].includes(
                response.status
            )
        );
    }
);


// =========================================================
// AUTHORIZATION HEADER
// =========================================================

test(
    "file download rejects malformed authorization header",
    async () => {

        const { user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response =
            await request(app)
                .get(
                    `/api/files/${file._id}/download`
                )
                .set(
                    "Authorization",
                    "InvalidToken"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// EMPTY BEARER TOKEN
// =========================================================

test(
    "file download rejects empty bearer token",
    async () => {

        const { user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response =
            await request(app)
                .get(
                    `/api/files/${file._id}/download`
                )
                .set(
                    "Authorization",
                    "Bearer "
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// PATH / S3 KEY LEAKAGE
// =========================================================

test(
    "download error does not expose S3 key",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const secretS3Key =
            `private/test-secret-${Date.now()}.txt`;

        const file =
            await createFile(
                user.id,
                {
                    s3Key: secretS3Key
                }
            );

        const response =
            await request(app)
                .get(
                    `/api/files/${file._id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(secretS3Key)
        );
    }
);


// =========================================================
// PATH TRAVERSAL ID
// =========================================================

test(
    "download rejects path traversal style ID",
    async () => {

        const { token } =
            await createUserAndLogin();

        const response =
            await request(app)
                .get(
                    "/api/files/../../etc/passwd/download"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// METHOD SECURITY
// =========================================================

test(
    "POST cannot be used as file download",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response =
            await request(app)
                .post(
                    `/api/files/${file._id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// =========================================================
// REPEATED REQUEST SAFETY
// =========================================================

test(
    "repeated invalid download requests do not cause 500",
    async () => {

        const { token } =
            await createUserAndLogin();

        for (let i = 0; i < 10; i++) {

            const response =
                await request(app)
                    .get(
                        `/api/files/000000000000000000000000/download`
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    );

            assert.notEqual(
                response.status,
                500
            );
        }
    }
);


// =========================================================
// RESPONSE LEAKAGE
// =========================================================

test(
    "download error does not expose internal server information",
    async () => {

        const { token } =
            await createUserAndLogin();

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-real-file/download"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        const body =
            JSON.stringify(response.body)
                .toLowerCase();

        assert.ok(
            !body.includes("node_modules")
        );

        assert.ok(
            !body.includes("src/controllers")
        );

        assert.ok(
            !body.includes("mongoose")
        );
    }
);