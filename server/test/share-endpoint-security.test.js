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
import Share from "../src/models/share.model.js";

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


const createUserAndLogin = async ({
    name = "Test User",
    email = `user-${Date.now()}-${Math.random()}@example.com`
} = {}) => {

    const password = "password123";

    // Give every test account a unique IP.
    // This prevents the production login rate limiter
    // from affecting this security test suite.
    const testIp =
        `10.80.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    const registerResponse =
        await request(app)
            .post("/api/auth/register")
            .set("X-Forwarded-For", testIp)
            .send({
                name,
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
        loginResponse.body?.token ||
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.accessToken;

    assert.ok(
        token,
        `No access token returned: ${JSON.stringify(loginResponse.body)}`
    );

    const user =
        await User.findOne({
            email
        });

    assert.ok(
        user,
        `User was not found in database: ${email}`
    );

    return {
        token,
        user
    };
};
  


const createFile = async (ownerId, overrides = {}) => {

    assert.ok(
        ownerId,
        "createFile() received an undefined ownerId"
    );

    return await File.create({
        owner: ownerId,

        originalName:
            overrides.originalName ||
            "test-document.txt",

        storedName:
            overrides.storedName ||
            `stored-${Date.now()}-${Math.random()}.txt`,

        s3Key:
            overrides.s3Key ||
            `test/${Date.now()}-${Math.random()}.txt`,

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
    "share creation requires authentication",
    async () => {

        const { user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// OWNERSHIP
// =========================================================

test(
    "user cannot create share for another user's file",
    async () => {

        const owner =
            await createUserAndLogin();

        const attacker =
            await createUserAndLogin();

        const file =
            await createFile(owner.user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${attacker.token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            403
        );

        const shares =
            await Share.find({
                file: file._id
            });

        assert.equal(
            shares.length,
            0
        );
    }
);


// =========================================================
// INVALID FILE ID
// =========================================================

test(
    "invalid MongoDB file ID is rejected safely",
    async () => {

        const { token } =
            await createUserAndLogin();

        const response = await request(app)
            .post(
                "/api/share/not-a-valid-mongodb-id"
            )
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

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
    "share cannot be created for non-existent file",
    async () => {

        const { token } =
            await createUserAndLogin();

        const mongoose =
            await import("mongoose");

        const fakeId =
            new mongoose.Types.ObjectId();

        const response = await request(app)
            .post(`/api/share/${fakeId}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            404
        );
    }
);


// =========================================================
// SUCCESSFUL SHARE CREATION
// =========================================================

test(
    "owner can create a share",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            201
        );

        assert.equal(
            response.body.success,
            true
        );

        assert.ok(
            response.body.shareId
        );

        assert.ok(
            response.body.shareLink
        );

        assert.ok(
            response.body.expiresAt
        );
    }
);


// =========================================================
// SHARE DATABASE RECORD
// =========================================================

test(
    "successful share creation creates database record",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            201
        );

        const share =
            await Share.findById(
                response.body.shareId
            );

        assert.ok(
            share
        );

        assert.equal(
            share.owner.toString(),
            user.id.toString()
        );

        assert.equal(
            share.file.toString(),
            file._id.toString()
        );

        assert.equal(
            share.maxDownloads,
            5
        );
    }
);


// =========================================================
// TOKEN SECURITY
// =========================================================

test(
    "share token is not stored in plaintext",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.equal(
            response.status,
            201
        );

        const share =
            await Share.findById(
                response.body.shareId
            );

        assert.ok(
            share
        );

        const shareLink =
            response.body.shareLink;

        const rawToken =
            shareLink.split("/").pop();

        assert.ok(
            rawToken
        );

        assert.notEqual(
            share.token,
            rawToken
        );

        assert.equal(
            share.token.length,
            64
        );
    }
);


// =========================================================
// PASSWORD VALIDATION
// =========================================================

test(
    "share password shorter than 8 characters is rejected",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5,
                password: "1234567"
            });

        assert.equal(
            response.status,
            400
        );
    }
);


test(
    "share password is accepted when valid",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5,
                password: "securepass123"
            });

        assert.equal(
            response.status,
            201
        );

        const share =
            await Share.findById(
                response.body.shareId
            );

        assert.ok(
            share.passwordHash
        );

        assert.notEqual(
            share.passwordHash,
            "securepass123"
        );
    }
);


// =========================================================
// MAX DOWNLOAD VALIDATION
// =========================================================

test(
    "maxDownloads must be a positive integer",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 0
            });

        assert.equal(
            response.status,
            400
        );
    }
);


test(
    "negative maxDownloads is rejected",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: -1
            });

        assert.equal(
            response.status,
            400
        );
    }
);


// =========================================================
// RESPONSE DATA LEAKAGE
// =========================================================

test(
    "share response does not expose encryption key",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(
                "test-encryption-key"
            )
        );

        assert.ok(
            !body.toLowerCase().includes(
                "encryptionkey"
            )
        );
    }
);


// =========================================================
// FILE PATH LEAKAGE
// =========================================================

test(
    "share response does not expose S3 key",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(
                file.s3Key
            )
        );
    }
);


// =========================================================
// OWNERSHIP INTEGRITY
// =========================================================

test(
    "creating a share does not modify file ownership",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        await request(app)
            .post(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        const unchangedFile =
            await File.findById(file._id);

        assert.ok(
            unchangedFile
        );

        assert.equal(
            unchangedFile.owner.toString(),
            user.id.toString()
        );
    }
);


// =========================================================
// HTTP METHOD SECURITY
// =========================================================

test(
    "GET request cannot create a share",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .get(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            );

        assert.notEqual(
            response.status,
            201
        );
    }
);


test(
    "PUT request cannot create a share",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        const response = await request(app)
            .put(`/api/share/${file._id}`)
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .send({
                maxDownloads: 5
            });

        assert.notEqual(
            response.status,
            201
        );
    }
);


// =========================================================
// RATE LIMITING
// =========================================================

test(
    "share creation rate limiter eventually blocks excessive requests",
    async () => {

        const { token, user } =
            await createUserAndLogin();

        const file =
            await createFile(user.id);

        let blocked = false;

        for (let i = 0; i < 30; i++) {

            const response = await request(app)
                .post(`/api/share/${file._id}`)
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    maxDownloads: 5
                });

            if (response.status === 429) {
                blocked = true;
                break;
            }
        }

        assert.equal(
            blocked,
            true
        );
    }
);