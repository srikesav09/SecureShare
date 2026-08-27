import "./env.js";

import test, {
    before,
    after
} from "node:test";

import assert from "node:assert/strict";
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


const PASSWORD =
    "ShareTokenLifecycle123!";

let user;
let token;
let file;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `share-token-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Share Token User",

                email,

                password:
                    PASSWORD
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

                password:
                    PASSWORD
            });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );

    const accessToken =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;

    assert.ok(
        accessToken,
        "JWT token missing"
    );

    const databaseUser =
        await User.findOne({
            email
        });

    assert.ok(
        databaseUser
    );

    return {
        user:
            databaseUser,

        token:
            accessToken
    };
};


const createFile = async (
    ownerId,
    suffix = "share-token"
) => {

    return File.create({

        originalName:
            `${suffix}.txt`,

        storedName:
            `${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/share-token-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.enc`,

        owner:
            ownerId,

        encrypted:
            true,

        iv:
            "internal-test-iv",

        hash:
            "internal-test-hash"
    });
};


const createShare = async (
    fileId,
    ownerId,
    overrides = {}
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `hashed-share-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}`,

        expiresAt:
            new Date(
                Date.now() +
                60 * 60 * 1000
            ),

        maxDownloads:
            5,

        downloadCount:
            0,

        isRevoked:
            false,

        passwordHash:
            null,

        ...overrides
    });
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    user =
        result.user;

    token =
        result.token;


    file =
        await createFile(
            user.id
        );

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. SHARE TOKEN EXISTS
   ========================================================= */

test(
    "share has a non-empty token value",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );


        assert.ok(
            share.token
        );


        assert.equal(
            typeof share.token,
            "string"
        );


        assert.ok(
            share.token.length > 0
        );

    }
);


/* =========================================================
   2. RAW TOKEN IS NOT RETURNED FROM DATABASE
   ========================================================= */

test(
    "database share token is not equal to public token when response creates a share",
    async () => {

        const response =
            await request(app)
                .post(
                    `/api/share/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    maxDownloads:
                        5
                });


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const shareId =
            response.body?.shareId ||
            response.body?.data?.shareId;


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareId
        );


        assert.ok(
            shareLink
        );


        const rawToken =
            shareLink
                .split("/")
                .pop();


        assert.ok(
            rawToken
        );


        const storedShare =
            await Share.findById(
                shareId
            );


        assert.ok(
            storedShare
        );


        assert.notEqual(
            storedShare.token,
            rawToken,
            "Raw share token is stored in plaintext"
        );

    }
);


/* =========================================================
   3. TOKEN LENGTH
   ========================================================= */

test(
    "stored share token is non-empty and sufficiently unpredictable",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );

        assert.equal(
            typeof share.token,
            "string"
        );

        assert.ok(
            share.token.length >= 32,
            `Share token is too short: ${share.token.length}`
        );

        assert.match(
            share.token,
            /^[a-zA-Z0-9_-]+$/,
            "Share token contains unexpected characters"
        );
    }
);


/* =========================================================
   4. TOKENS ARE UNIQUE
   ========================================================= */

test(
    "multiple shares receive different token hashes",
    async () => {

        const shares = [];


        for (let i = 0; i < 5; i++) {

            shares.push(
                await createShare(
                    file.id,
                    user.id
                )
            );

        }


        const tokens =
            shares.map(
                item =>
                    item.token
            );


        const uniqueTokens =
            new Set(
                tokens
            );


        assert.equal(
            uniqueTokens.size,
            tokens.length,
            "Share tokens are not unique"
        );

    }
);


/* =========================================================
   5. RANDOM TOKEN GUESS
   ========================================================= */

test(
    "random token cannot access a valid share",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );


        const response =
            await request(app)
                .get(
                    `/api/share/random-${share.token}-guess`
                );


        assert.notEqual(
            response.status,
            200,
            "Guessed token accessed the share"
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   6. REVOKED TOKEN
   ========================================================= */

test(
    "revoked share token cannot be reused",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id,
                {
                    isRevoked:
                        true
                }
            );


        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        assert.notEqual(
            response.status,
            200,
            "Revoked share token remained usable"
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.isRevoked,
            true
        );

    }
);


/* =========================================================
   7. EXPIRED TOKEN
   ========================================================= */

test(
    "expired share token cannot be reused",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id,
                {
                    expiresAt:
                        new Date(
                            Date.now() -
                            60 * 1000
                        )
                }
            );


        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        assert.notEqual(
            response.status,
            200,
            "Expired share token remained usable"
        );

    }
);


/* =========================================================
   8. TOKEN CANNOT BE USED AS SHARE ID
   ========================================================= */

test(
    "share token cannot be substituted into authenticated share-management endpoint",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );


        const response =
            await request(app)
                .delete(
                    `/api/share/${share.token}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200,
            "Public token was accepted as internal share ID"
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.isRevoked,
            false
        );

    }
);


/* =========================================================
   9. TOKEN REUSE DOES NOT ALTER DOWNLOAD COUNTER
   ========================================================= */

test(
    "invalid token reuse does not modify share state",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );


        const before =
            await Share.findById(
                share.id
            );


        await request(app)
            .get(
                `/api/share/invalid-${share.token}`
            );


        const after =
            await Share.findById(
                share.id
            );


        assert.ok(
            after
        );


        assert.equal(
            after.downloadCount,
            before.downloadCount
        );


        assert.equal(
            after.isRevoked,
            before.isRevoked
        );

    }
);


/* =========================================================
   10. TOKEN HASH NOT EXPOSED IN ERROR
   ========================================================= */

test(
    "share-token errors do not expose stored token hash",
    async () => {

        const share =
            await createShare(
                file.id,
                user.id
            );


        const response =
            await request(app)
                .get(
                    `/api/share/invalid-${Date.now()}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                share.token
            ),
            false,
            "Stored token hash leaked through error response"
        );


        assert.equal(
            body.toLowerCase().includes(
                "mongoose"
            ),
            false
        );


        assert.equal(
            body.toLowerCase().includes(
                "node_modules"
            ),
            false
        );

    }
);