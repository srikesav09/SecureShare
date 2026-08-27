import "./env.js";

import assert from "node:assert/strict";
import test, { before, after, beforeEach } from "node:test";
import request from "supertest";
import jwt from "jsonwebtoken";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";
import Share from "../src/models/share.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const PASSWORD = "TestPassword123!";

let owner;
let otherUser;
let file;
let share;
let ownerToken;
let otherUserToken;

const registerAndLogin = async (name) => {

    const email =
        `revoke-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}@example.com`;

    const password = PASSWORD;

    // Give every test account a unique client IP.
    // This prevents the production login rate limiter
    // from interfering with the security test suite.
    const testIp =
        `10.90.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    // ========================================================
    // REGISTER
    // ========================================================

    const register = await request(app)
        .post("/api/auth/register")
        .set("X-Forwarded-For", testIp)
        .send({
            name,
            email,
            password
        });

    assert.ok(
        [200, 201].includes(register.status),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    // ========================================================
    // LOGIN
    // ========================================================

    const login = await request(app)
        .post("/api/auth/login")
        .set("X-Forwarded-For", testIp)
        .send({
            email,
            password
        });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );

    // ========================================================
    // TOKEN
    // ========================================================

    const token =
        login.body?.token ||
        login.body?.accessToken ||
        login.body?.data?.token ||
        login.body?.data?.accessToken;

    assert.ok(
        token,
        `No access token returned: ${JSON.stringify(login.body)}`
    );

    // ========================================================
    // REAL DATABASE USER
    // ========================================================

    const user = await User.findOne({
        email
    });

    assert.ok(
        user,
        `User was not found in database: ${email}`
    );

    return {
        token,
        user,
        email
    };
};


/*
 * Start isolated MongoDB database.
 */
before(async () => {

    await startTestDatabase();

});


/*
 * Create fresh users/file/share before every test.
 */
beforeEach(async () => {

    await clearTestDatabase();

    const ownerResult =
        await registerAndLogin("Owner User");

    owner = ownerResult.user;
    ownerToken = ownerResult.token;


    const otherResult =
        await registerAndLogin("Other User");

    otherUser = otherResult.user;
    otherUserToken = otherResult.token;


    /*
     * Create a file owned by owner.
     *
     * We do not actually upload to S3 here because these tests
     * are testing SHARE REVOCATION authorization.
     */
    file = await File.create({

        originalName: "revocation-test.txt",

        storedName:
            `revocation-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}.txt`,

        mimeType: "text/plain",

        size: 100,

        s3Key:
            `test/revocation-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}.enc`,

        owner: owner.id,

        encrypted: true,

        iv: "test-iv",

        hash: "test-hash"
    });


    /*
     * Create the share directly in MongoDB.
     *
     * This avoids depending on S3/share creation for these
     * revocation authorization tests.
     */
    share = await Share.create({

        file: file.id,

        owner: owner.id,

        token:
            `hashed-token-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}`,

        expiresAt:
            new Date(Date.now() + 60 * 60 * 1000),

        maxDownloads: null,

        downloadCount: 0,

        isRevoked: false,

        passwordHash: null
    });

});


after(async () => {

    await stopTestDatabase();

});


test(
    "unauthenticated user cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .delete(`/api/share/${share.id}`);

        assert.equal(
            response.status,
            401
        );

        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            false
        );
    }
);


test(
    "malformed share ID is rejected",
    async () => {

        const response =
            await request(app)
                .delete("/api/share/not-a-valid-id")
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            response.status,
            400
        );
    }
);


test(
    "nonexistent share cannot be revoked",
    async () => {

        const fakeShareId =
            "507f1f77bcf86cd799439011";

        const response =
            await request(app)
                .delete(`/api/share/${fakeShareId}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            response.status,
            404
        );
    }
);


test(
    "another user cannot revoke owner's share",
    async () => {

        const response =
            await request(app)
                .delete(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${otherUserToken}`
                );

        assert.equal(
            response.status,
            403
        );

        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            false
        );

        assert.equal(
            databaseShare.owner.toString(),
            owner.id
        );
    }
);


test(
    "changing client-side user ID cannot bypass ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?userId=${owner.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${otherUserToken}`
                );

        assert.equal(
            response.status,
            403
        );

        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            false
        );
    }
);


test(
    "query parameters cannot bypass share ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?ownerId=${owner.id}&userId=${owner.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${otherUserToken}`
                );

        assert.equal(
            response.status,
            403
        );

        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            false
        );
    }
);


test(
    "share owner can revoke their own share",
    async () => {

        const response =
            await request(app)
                .delete(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            response.status,
            200
        );

        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            true
        );
    }
);


test(
    "already revoked share cannot be revoked again",
    async () => {

        await Share.findByIdAndUpdate(
            share.id,
            {
                $set: {
                    isRevoked: true
                }
            }
        );


        const response =
            await request(app)
                .delete(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            response.status,
            400
        );


        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            true
        );
    }
);


test(
    "revocation cannot be bypassed with a second request",
    async () => {

        const firstResponse =
            await request(app)
                .delete(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            firstResponse.status,
            200
        );


        const secondResponse =
            await request(app)
                .delete(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            secondResponse.status,
            400
        );


        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            true
        );
    }
);


test(
    "GET request cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .get(`/api/share/${share.id}`)
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        /*
         * There is no GET route for /api/share/:shareId.
         * Therefore GET must not perform revocation.
         */
        assert.equal(
            response.status,
            404
        );


        const databaseShare =
            await Share.findById(share.id);

        assert.equal(
            databaseShare.isRevoked,
            false
        );
    }
);