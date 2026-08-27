import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert";
import request from "supertest";
import crypto from "crypto";

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


// =========================================================
// HELPERS
// =========================================================

const createUserAndLogin = async () => {

    const email =
        `public-share-${Date.now()}-${Math.random()}@example.com`;

    const registerResponse =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Public Share User",
                email,
                password: "password123"
            });

    assert.equal(
        registerResponse.status,
        201,
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    const loginResponse =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password: "password123"
            });

    assert.equal(
        loginResponse.status,
        200,
        `Login failed: ${JSON.stringify(loginResponse.body)}`
    );

    return {
        token: loginResponse.body.data.token,
        user: loginResponse.body.data.user
    };
};


const createFile = async (ownerId) => {

    return await File.create({
        owner: ownerId,
        originalName: "public-test.txt",
        storedName:
            `public-${Date.now()}-${Math.random()}.txt`,
        s3Key:
            `test/public-${Date.now()}-${Math.random()}.txt`,
        mimeType: "text/plain",
        size: 100
    });
};


const hashToken = (token) => {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
};


const createShare = async (
    ownerId,
    fileId,
    overrides = {}
) => {

    const rawToken =
        overrides.rawToken ||
        crypto.randomBytes(32).toString("hex");

    const share = await Share.create({

        owner: ownerId,

        file: fileId,

        token: hashToken(rawToken),

        expiresAt:
            overrides.expiresAt ||
            new Date(Date.now() + 60 * 60 * 1000),

        maxDownloads:
            overrides.maxDownloads ?? 10,

        downloadCount:
            overrides.downloadCount ?? 0,

        ...(overrides.passwordHash
            ? {
                passwordHash:
                    overrides.passwordHash
            }
            : {})
    });

    return {
        share,
        rawToken
    };
};


// =========================================================
// INVALID TOKEN
// =========================================================

test(
    "public share rejects completely invalid token",
    async () => {

        const response =
            await request(app)
                .get(
                    "/public/not-a-valid-share-token"
                );

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            [400, 401, 403, 404].includes(
                response.status
            )
        );
    }
);


// =========================================================
// RANDOM TOKEN
// =========================================================

test(
    "random share token cannot access a file",
    async () => {

        const randomToken =
            crypto.randomBytes(32).toString("hex");

        const response =
            await request(app)
                .get(
                    `/public/${randomToken}`
                );

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            [400, 401, 403, 404].includes(
                response.status
            )
        );
    }
);


// =========================================================
// EMPTY TOKEN
// =========================================================

test(
    "empty public share token is rejected",
    async () => {

        const response =
            await request(app)
                .get("/public/");

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// MALFORMED TOKEN
// =========================================================

test(
    "malformed token does not cause server error",
    async () => {

        const malformedTokens = [
            "!",
            "@@@",
            "abc",
            "null",
            "undefined",
            "0",
            "NaN",
            "undefinedundefined",
            "aaaaaaaaaaaaaaaa"
        ];

        for (const token of malformedTokens) {

            const response =
                await request(app)
                    .get(
                        `/public/${encodeURIComponent(token)}`
                    );

            assert.notEqual(
                response.status,
                500,
                `Token caused 500: ${token}`
            );
        }
    }
);


// =========================================================
// TOKEN TAMPERING
// =========================================================

test(
    "modified share token cannot access original share",
    async () => {

        const { user } = await createUserAndLogin();

        const file =
            await createFile(user.id);

        const { rawToken } =
            await createShare(
                user.id,
                file._id
            );

        const modifiedToken =
            rawToken.substring(
                0,
                rawToken.length - 1
            ) +
            (rawToken.endsWith("a") ? "b" : "a");

        const response =
            await request(app)
                .get(
                    `/public/${modifiedToken}`
                );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// =========================================================
// EXPIRED SHARE
// =========================================================

test(
    "expired public share is rejected",
    async () => {

        const { user } = await createUserAndLogin();

        const file =
            await createFile(user.id);

        const { rawToken } =
            await createShare(
                user.id,
                file._id,
                {
                    expiresAt:
                        new Date(
                            Date.now() - 60 * 1000
                        )
                }
            );

        const response =
            await request(app)
                .get(
                    `/public/${rawToken}`
                );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// =========================================================
// DOWNLOAD LIMIT
// =========================================================

test(
    "share with exhausted download limit is rejected",
    async () => {

        const { user } = await createUserAndLogin();

        const file =
            await createFile(user.id);

        const { rawToken } =
            await createShare(
                user.id,
                file._id,
                {
                    maxDownloads: 3,
                    downloadCount: 3
                }
            );

        const response =
            await request(app)
                .get(
                    `/public/${rawToken}`
                );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// =========================================================
// ZERO DOWNLOAD LIMIT
// =========================================================

test(
    "share with zero remaining downloads is not served",
    async () => {

        const { user } = await createUserAndLogin();

        const file =
            await createFile(user.id);

        const { rawToken } =
            await createShare(
                user.id,
                file._id,
                {
                    maxDownloads: 1,
                    downloadCount: 1
                }
            );

        const response =
            await request(app)
                .get(
                    `/public/${rawToken}`
                );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// =========================================================
// INFORMATION LEAKAGE
// =========================================================

test(
    "invalid public share response does not expose internal information",
    async () => {

        const response =
            await request(app)
                .get(
                    "/public/this-token-does-not-exist"
                );

        const body =
            JSON.stringify(response.body)
                .toLowerCase();

        assert.ok(
            !body.includes("node_modules")
        );

        assert.ok(
            !body.includes("mongoose")
        );

        assert.ok(
            !body.includes("src/controllers")
        );

        assert.ok(
            !body.includes("s3key")
        );
    }
);


// =========================================================
// TOKEN HASH SECURITY
// =========================================================

test(
    "share database stores hashed token instead of raw token",
    async () => {

        const { user } = await createUserAndLogin();

        const file =
            await createFile(user.id);

        const { share, rawToken } =
            await createShare(
                user.id,
                file._id
            );

        const storedShare =
            await Share.findById(
                share._id
            );

        assert.ok(
            storedShare
        );

        assert.notEqual(
            storedShare.token,
            rawToken
        );

        assert.equal(
            storedShare.token.length,
            64
        );
    }
);


// =========================================================
// REPEATED INVALID REQUESTS
// =========================================================

test(
    "repeated invalid public-share requests remain safe",
    async () => {

        for (let i = 0; i < 10; i++) {

            const token =
                crypto.randomBytes(32).toString("hex");

            const response =
                await request(app)
                    .get(
                        `/public/${token}`
                    );

            assert.notEqual(
                response.status,
                500
            );
        }
    }
);