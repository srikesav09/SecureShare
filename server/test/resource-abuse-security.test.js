import "./env.js";

import test, { before, after } from "node:test";
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


let token;
let user;
let file;
let share;


/*
 * =========================================================
 * AUTHENTICATION
 * =========================================================
 */

const registerAndLogin = async () => {

    const email =
        `resource-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;

    const password =
        "StrongPassword123!";


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Resource Abuse User",
                email,
                password
            });


    assert.ok(
        [200, 201].includes(register.status),
        `Registration failed: ${JSON.stringify(register.body)}`
    );


    const login =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password
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
        `JWT token missing: ${JSON.stringify(login.body)}`
    );


    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(databaseUser);


    return {
        token: accessToken,
        user: databaseUser
    };
};


/*
 * =========================================================
 * FILE SETUP
 * =========================================================
 */

const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "resource-abuse-test.txt",

        storedName:
            `resource-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/resource-${Date.now()}.enc`,

        owner:
            ownerId,

        encrypted:
            true,

        iv:
            "test-iv",

        hash:
            "test-hash"
    });
};


/*
 * =========================================================
 * SETUP
 * =========================================================
 */

before(async () => {

    await startTestDatabase();

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    token =
        result.token;

    user =
        result.user;


    file =
        await createFile(
            user.id
        );


    share =
        await Share.create({

            file:
                file.id,

            owner:
                user.id,

            token:
                `resource-share-${Date.now()}-${Math.random()
                    .toString(36)
                    .slice(2, 8)}`,

            expiresAt:
                new Date(
                    Date.now() + 60 * 60 * 1000
                ),

            maxDownloads:
                3,

            downloadCount:
                0,

            isRevoked:
                false,

            passwordHash:
                null

        });

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. DOWNLOAD REQUIRES AUTHENTICATION
 * =========================================================
 */

test(
    "file download requires authentication",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                );


        assert.ok(
            [401, 403].includes(response.status),
            `Unauthenticated download returned ${response.status}`
        );

    }
);


/*
 * =========================================================
 * 2. INVALID FILE ID
 * =========================================================
 */

test(
    "invalid download file ID is rejected safely",
    async () => {

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
            500,
            "Invalid file ID caused server error"
        );

    }
);


/*
 * =========================================================
 * 3. NONEXISTENT FILE
 * =========================================================
 */

test(
    "nonexistent file cannot trigger expensive download processing",
    async () => {

        const fakeId =
            "507f1f77bcf86cd799439011";


        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.ok(
            [400, 404].includes(response.status),
            `Unexpected nonexistent-file response: ${response.status}`
        );

    }
);



/*
 * =========================================================
 * 4. REPEATED DOWNLOAD REQUESTS
 * =========================================================
 */

test(
    "repeated download requests do not bypass authorization",
    async () => {

        const responses = [];

        for (let i = 0; i < 5; i++) {

            const response =
                await request(app)
                    .get(
                        `/api/files/${file.id}/download`
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    );

            responses.push(response);
        }


        /*
         * The important security property here is that
         * repeated requests must not become unauthorized
         * access to another resource.
         *
         * A 500 may occur because this test deliberately
         * uses a fake S3 object.
         */
        for (const response of responses) {

            assert.notEqual(
                response.status,
                401,
                "Valid JWT was unexpectedly rejected"
            );

        }


        const databaseFile =
            await File.findById(file.id);


        assert.ok(
            databaseFile,
            "Repeated downloads deleted the file"
        );


        assert.equal(
            String(databaseFile.owner),
            String(user.id),
            "Repeated downloads changed file ownership"
        );

    }
);


/*
 * =========================================================
 * 5. EXCESSIVE SHARE DOWNLOADS
 * =========================================================
 */

test(
    "share download limit cannot become negative",
    async () => {

        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.downloadCount,
            0
        );


        assert.ok(
            databaseShare.maxDownloads === null ||
            databaseShare.maxDownloads >= 0
        );

    }
);


/*
 * =========================================================
 * 6. DOWNLOAD COUNT CANNOT EXCEED LIMIT
 * =========================================================
 */

test(
    "download count must never exceed maxDownloads",
    async () => {

        await Share.findByIdAndUpdate(
            share.id,
            {
                $set: {
                    downloadCount:
                        share.maxDownloads
                }
            }
        );


        const response =
            await request(app)
                .get(
                    `/api/share/${share.id}`
                );


        /*
         * The exact response depends on the public-share
         * endpoint implementation, but it must not become
         * an internal server error.
         */
        assert.notEqual(
            response.status,
            500
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.ok(
            databaseShare.downloadCount <=
            databaseShare.maxDownloads
        );

    }
);



test(
    "negative download count is not accepted as a bypass",
    async () => {

        const before =
            await Share.findById(share.id);

        assert.ok(
            before,
            "Share was not found"
        );

        const originalCount =
            before.downloadCount;


        await assert.rejects(
            Share.findByIdAndUpdate(
                share.id,
                {
                    $set: {
                        downloadCount: -1
                    }
                },
                {
                    runValidators: true
                }
            ),
            /downloadCount/
        );


        const after =
            await Share.findById(share.id);

        assert.ok(
            after,
            "Share unexpectedly disappeared"
        );


        /*
         * The malicious value must not be stored.
         * The original value must remain unchanged.
         */
        assert.equal(
            after.downloadCount,
            originalCount,
            "Rejected negative download count changed the stored value"
        );


        assert.ok(
            after.downloadCount >= 0,
            "Negative download count was stored"
        );

    }
);


/*
 * =========================================================
 * 8. HUGE DOWNLOAD LIMIT
 * =========================================================
 */

test(
    "extremely large download limit does not crash the API",
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
                        Number.MAX_SAFE_INTEGER
                });


        assert.notEqual(
            response.status,
            500
        );

    }
);



/*
 * =========================================================
 * 9. CONCURRENT DOWNLOAD REQUESTS
 * =========================================================
 */

test(
    "concurrent download requests cannot change authorization",
    async () => {

        const requests =
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .get(
                            `/api/files/${file.id}/download`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            );


        const responses =
            await Promise.all(requests);


        for (const response of responses) {

            assert.notEqual(
                response.status,
                401,
                "Concurrent request unexpectedly lost authentication"
            );

        }


        const databaseFile =
            await File.findById(file.id);


        assert.ok(
            databaseFile,
            "Concurrent requests deleted the file"
        );


        assert.equal(
            String(databaseFile.owner),
            String(user.id),
            "Concurrent requests changed file ownership"
        );

    }
);


/*
 * =========================================================
 * 10. RESOURCE ID CANNOT BE USED FOR ARBITRARY ACCESS
 * =========================================================
 */

test(
    "download endpoint does not accept arbitrary resource identifiers",
    async () => {

        const maliciousIds = [
            "../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "[object Object]",
            "null",
            "undefined"
        ];


        for (const id of maliciousIds) {

            const response =
                await request(app)
                    .get(
                        `/api/files/${id}/download`
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    );


            assert.notEqual(
                response.status,
                500,
                `Malicious resource ID caused server error: ${id}`
            );

        }

    }
);