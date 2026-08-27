import "./env.js";

import test, {
    before,
    after,
    beforeEach
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


const PASSWORD = "RaceSecurity123!";

let user;
let token;
let file;
let share;


/* =========================================================
   HELPERS
   ========================================================= */

const createUserAndLogin = async () => {

    const email =
        `race-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Race Security User",
                email,
                password: PASSWORD
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
                password: PASSWORD
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


    assert.ok(
        databaseUser,
        "User was not created"
    );


    return {
        user: databaseUser,
        token: accessToken
    };
};


const createTestFile = async (ownerId) => {

    return File.create({

        originalName:
            "race-test.txt",

        storedName:
            `race-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/race-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.enc`,

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


const createTestShare = async (
    fileId,
    ownerId,
    maxDownloads
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `race-token-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}`,

        expiresAt:
            new Date(
                Date.now() +
                60 * 60 * 1000
            ),

        maxDownloads,

        downloadCount:
            0,

        isRevoked:
            false,

        passwordHash:
            null

    });
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();


    const result =
        await createUserAndLogin();


    user =
        result.user;

    token =
        result.token;


    file =
        await createTestFile(
            user.id
        );

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. DATABASE LEVEL ATOMIC LIMIT
   ========================================================= */

test(
    "single-download limit cannot be consumed more than once atomically",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                1
            );


        const attempts =
            Array.from(
                {
                    length: 10
                },
                () =>
                    Share.findOneAndUpdate(
                        {
                            _id: share.id,

                            $or: [
                                {
                                    maxDownloads:
                                        null
                                },
                                {
                                    $expr: {
                                        $lt: [
                                            "$downloadCount",
                                            "$maxDownloads"
                                        ]
                                    }
                                }
                            ]
                        },
                        {
                            $inc: {
                                downloadCount:
                                    1
                            }
                        },
                        {
                            new: true
                        }
                    )
            );


        const results =
            await Promise.all(
                attempts
            );


        const successfulClaims =
            results.filter(
                Boolean
            );


        /*
         * With maxDownloads = 1, exactly one concurrent
         * atomic claim should succeed.
         */
        assert.equal(
            successfulClaims.length,
            1,
            `Expected exactly one successful claim, got ${successfulClaims.length}`
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.downloadCount,
            1
        );

    }
);


/* =========================================================
   2. LIMIT OF 3
   ========================================================= */

test(
    "three-download limit cannot be exceeded by concurrent claims",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                3
            );


        const attempts =
            Array.from(
                {
                    length: 20
                },
                () =>
                    Share.findOneAndUpdate(
                        {
                            _id: share.id,

                            $or: [
                                {
                                    maxDownloads:
                                        null
                                },
                                {
                                    $expr: {
                                        $lt: [
                                            "$downloadCount",
                                            "$maxDownloads"
                                        ]
                                    }
                                }
                            ]
                        },
                        {
                            $inc: {
                                downloadCount:
                                    1
                            }
                        },
                        {
                            new: true
                        }
                    )
            );


        const results =
            await Promise.all(
                attempts
            );


        const successfulClaims =
            results.filter(
                Boolean
            );


        assert.equal(
            successfulClaims.length,
            3,
            `Expected exactly three claims, got ${successfulClaims.length}`
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.downloadCount,
            3
        );


        assert.ok(
            databaseShare.downloadCount <=
            databaseShare.maxDownloads
        );

    }
);


/* =========================================================
   3. EXTRA CLAIM AFTER LIMIT
   ========================================================= */

test(
    "claim after maxDownloads is exhausted is rejected",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                1
            );


        const first =
            await Share.findOneAndUpdate(
                {
                    _id:
                        share.id,

                    $expr: {
                        $lt: [
                            "$downloadCount",
                            "$maxDownloads"
                        ]
                    }
                },
                {
                    $inc: {
                        downloadCount:
                            1
                    }
                },
                {
                    new: true
                }
            );


        assert.ok(
            first
        );


        const second =
            await Share.findOneAndUpdate(
                {
                    _id:
                        share.id,

                    $expr: {
                        $lt: [
                            "$downloadCount",
                            "$maxDownloads"
                        ]
                    }
                },
                {
                    $inc: {
                        downloadCount:
                            1
                    }
                },
                {
                    new: true
                }
            );


        assert.equal(
            second,
            null,
            "Share was consumed after its download limit was exhausted"
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.downloadCount,
            1
        );

    }
);


/* =========================================================
   4. REPEATED ATOMIC CLAIMS
   ========================================================= */

test(
    "repeated atomic claims cannot exceed the configured limit",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                5
            );


        for (let i = 0; i < 25; i++) {

            await Share.findOneAndUpdate(
                {
                    _id:
                        share.id,

                    $expr: {
                        $lt: [
                            "$downloadCount",
                            "$maxDownloads"
                        ]
                    }
                },
                {
                    $inc: {
                        downloadCount:
                            1
                    }
                },
                {
                    new: true
                }
            );

        }


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            databaseShare.downloadCount,
            5
        );

    }
);


/* =========================================================
   5. REVOKED SHARE CANNOT BE CLAIMED
   ========================================================= */

test(
    "revoked share cannot be consumed",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                5
            );


        await Share.findByIdAndUpdate(
            share.id,
            {
                $set: {
                    isRevoked:
                        true
                }
            }
        );


        const result =
            await Share.findOneAndUpdate(
                {
                    _id:
                        share.id,

                    isRevoked:
                        false,

                    $expr: {
                        $lt: [
                            "$downloadCount",
                            "$maxDownloads"
                        ]
                    }
                },
                {
                    $inc: {
                        downloadCount:
                            1
                    }
                },
                {
                    new: true
                }
            );


        assert.equal(
            result,
            null
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.downloadCount,
            0
        );

    }
);


/* =========================================================
   6. EXPIRED SHARE CANNOT BE CLAIMED
   ========================================================= */

test(
    "expired share cannot be consumed",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                5
            );


        await Share.findByIdAndUpdate(
            share.id,
            {
                $set: {
                    expiresAt:
                        new Date(
                            Date.now() -
                            1000
                        )
                }
            }
        );


        const result =
            await Share.findOneAndUpdate(
                {
                    _id:
                        share.id,

                    expiresAt: {
                        $gt:
                            new Date()
                    },

                    $expr: {
                        $lt: [
                            "$downloadCount",
                            "$maxDownloads"
                        ]
                    }
                },
                {
                    $inc: {
                        downloadCount:
                            1
                    }
                },
                {
                    new: true
                }
            );


        assert.equal(
            result,
            null
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.downloadCount,
            0
        );

    }
);


/* =========================================================
   7. ZERO LIMIT CANNOT BE CONSUMED
   ========================================================= */

/* =========================================================
   7. ZERO LIMIT IS REJECTED
   ========================================================= */

test(
    "zero download limit is rejected",
    async () => {

        await assert.rejects(
            Share.create({
                file:
                    file.id,

                owner:
                    user.id,

                token:
                    `zero-limit-${Date.now()}-${Math.random()
                        .toString(36)
                        .slice(2, 8)}`,

                expiresAt:
                    new Date(
                        Date.now() +
                        60 * 60 * 1000
                    ),

                maxDownloads:
                    0,

                downloadCount:
                    0,

                isRevoked:
                    false,

                passwordHash:
                    null
            }),
            /maxDownloads/
        );


        /*
         * Confirm that no invalid zero-limit share
         * was persisted.
         */
        const invalidShares =
            await Share.find({
                file: file.id,
                owner: user.id,
                maxDownloads: 0
            });


        assert.equal(
            invalidShares.length,
            0,
            "Invalid zero-limit share was stored"
        );

    }
);


/* =========================================================
   8. NEGATIVE COUNT CANNOT CREATE EXTRA DOWNLOADS
   ========================================================= */

test(
    "negative download count cannot be used to gain unlimited downloads",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                3
            );


        /*
         * Mongoose validation should reject the malicious
         * negative value.
         */
        await assert.rejects(
            Share.findByIdAndUpdate(
                share.id,
                {
                    $set: {
                        downloadCount:
                            -100
                    }
                },
                {
                    runValidators:
                        true
                }
            ),
            /downloadCount/
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.downloadCount,
            0
        );

    }
);


/* =========================================================
   9. CONCURRENT CLAIMS PRESERVE OWNER
   ========================================================= */

test(
    "concurrent download claims cannot modify share ownership",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                2
            );


        const originalOwner =
            String(share.owner);


        const attempts =
            Array.from(
                {
                    length: 10
                },
                () =>
                    Share.findOneAndUpdate(
                        {
                            _id:
                                share.id,

                            $expr: {
                                $lt: [
                                    "$downloadCount",
                                    "$maxDownloads"
                                ]
                            }
                        },
                        {
                            $inc: {
                                downloadCount:
                                    1
                            }
                        },
                        {
                            new: true
                        }
                    )
            );


        await Promise.all(
            attempts
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare
        );


        assert.equal(
            String(databaseShare.owner),
            originalOwner
        );


        assert.equal(
            String(databaseShare.file),
            String(file.id)
        );


        assert.ok(
            databaseShare.downloadCount <= 2
        );

    }
);


/* =========================================================
   10. FINAL COUNT INVARIANT
   ========================================================= */

test(
    "concurrent claims always preserve downloadCount <= maxDownloads",
    async () => {

        share =
            await createTestShare(
                file.id,
                user.id,
                7
            );


        const attempts =
            Array.from(
                {
                    length: 50
                },
                () =>
                    Share.findOneAndUpdate(
                        {
                            _id:
                                share.id,

                            $expr: {
                                $lt: [
                                    "$downloadCount",
                                    "$maxDownloads"
                                ]
                            }
                        },
                        {
                            $inc: {
                                downloadCount:
                                    1
                            }
                        },
                        {
                            new: true
                        }
                    )
            );


        await Promise.all(
            attempts
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            databaseShare.downloadCount >= 0
        );


        assert.ok(
            databaseShare.downloadCount <=
            databaseShare.maxDownloads
        );


        assert.equal(
            databaseShare.downloadCount,
            7
        );

    }
);