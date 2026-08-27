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


const PASSWORD =
    "ShareCreationSecurity123!";

let user;
let token;
let file;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `share-abuse-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Share Abuse User",

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
        login.body?.accessToken ||
        login.body?.data?.accessToken;


    assert.ok(
        accessToken,
        `JWT token missing: ${JSON.stringify(login.body)}`
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
    suffix = "share-abuse"
) => {

    return File.create({

        originalName:
            `${suffix}.txt`,

        storedName:
            `${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.enc`,

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


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

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
   1. NORMAL SHARE CREATION
   ========================================================= */

test(
    "owner can create a normal share",
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


        assert.equal(
            response.body.success,
            true
        );

    }
);


/* =========================================================
   2. DUPLICATE SHARE CREATION
   ========================================================= */

test(
    "repeated share creation does not corrupt existing shares",
    async () => {

        const responses = [];


        for (let i = 0; i < 5; i++) {

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


            responses.push(
                response
            );


            assert.notEqual(
                response.status,
                500,
                `Share request ${i + 1} caused server error`
            );

        }


        const shares =
            await Share.find({
                file:
                    file.id,

                owner:
                    user.id
            });


        assert.ok(
            shares.length >= 1
        );


        for (
            const share
            of shares
        ) {

            assert.equal(
                String(share.file),
                String(file.id)
            );


            assert.equal(
                String(share.owner),
                String(user.id)
            );

        }

    }
);


/* =========================================================
   3. MAX DOWNLOADS ZERO
   ========================================================= */

test(
    "zero maxDownloads is rejected",
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
                        0
                });


        assert.equal(
            response.status,
            400
        );


        const shares =
            await Share.find({
                file:
                    file.id
            });


        assert.equal(
            shares.length,
            0
        );

    }
);


/* =========================================================
   4. NEGATIVE LIMIT
   ========================================================= */

test(
    "negative maxDownloads is rejected",
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
                        -100
                });


        assert.equal(
            response.status,
            400
        );


        const shares =
            await Share.find({
                file:
                    file.id
            });


        assert.equal(
            shares.length,
            0
        );

    }
);


/* =========================================================
   5. FRACTIONAL LIMIT
   ========================================================= */

test(
    "fractional maxDownloads is rejected",
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
                        2.5
                });


        assert.equal(
            response.status,
            400
        );


        const shares =
            await Share.find({
                file:
                    file.id
            });


        assert.equal(
            shares.length,
            0
        );

    }
);


/* =========================================================
   6. STRING LIMIT
   ========================================================= */

test(
    "string maxDownloads cannot bypass numeric validation",
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
                        "999999"
                });


        assert.ok(
            [400, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status}`
        );


        if (
            response.status === 201
        ) {

            const created =
                await Share.findOne({
                    file:
                        file.id,

                    owner:
                        user.id
                });


            assert.ok(
                created
            );


            assert.equal(
                typeof created.maxDownloads,
                "number",
                "String limit was stored as non-numeric data"
            );

        }

    }
);


/* =========================================================
   7. OBJECT LIMIT
   ========================================================= */

test(
    "object maxDownloads cannot bypass validation",
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
                    maxDownloads: {
                        value:
                            5
                    }
                });


        assert.equal(
            response.status,
            400
        );


        const shares =
            await Share.find({
                file:
                    file.id
            });


        assert.equal(
            shares.length,
            0
        );

    }
);


/* =========================================================
   8. CLIENT CANNOT SET OWNER
   ========================================================= */

test(
    "client cannot assign a different share owner",
    async () => {

        const fakeOwner =
            "507f1f77bcf86cd799439011";


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
                        5,

                    owner:
                        fakeOwner,

                    userId:
                        fakeOwner

                });


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const created =
            await Share.findOne({
                file:
                    file.id,

                owner:
                    user.id
            });


        assert.ok(
            created,
            "Share was not owned by authenticated user"
        );


        assert.notEqual(
            String(created.owner),
            fakeOwner,
            "Client-supplied owner became share owner"
        );

    }
);


/* =========================================================
   9. CLIENT CANNOT CHANGE FILE OWNER
   ========================================================= */

test(
    "share creation cannot modify file ownership",
    async () => {

        const originalOwner =
            String(file.owner);


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
                        5,

                    owner:
                        "507f1f77bcf86cd799439011",

                    fileOwner:
                        "507f1f77bcf86cd799439011",

                    userId:
                        "507f1f77bcf86cd799439011"

                });


        assert.notEqual(
            response.status,
            500
        );


        const unchangedFile =
            await File.findById(
                file.id
            );


        assert.ok(
            unchangedFile
        );


        assert.equal(
            String(unchangedFile.owner),
            originalOwner,
            "Share request changed file ownership"
        );

    }
);


/* =========================================================
   10. MANY SHARE REQUESTS
   ========================================================= */

test(
    "many share requests cannot create malformed share records",
    async () => {

        for (let i = 0; i < 25; i++) {

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


            assert.notEqual(
                response.status,
                500,
                `Share request ${i + 1} crashed the server`
            );

        }


        const shares =
            await Share.find({
                file:
                    file.id,

                owner:
                    user.id
            });


        for (
            const share
            of shares
        ) {

            assert.ok(
                share.maxDownloads === null ||
                (
                    Number.isInteger(
                        share.maxDownloads
                    ) &&
                    share.maxDownloads >= 1
                ),
                "Malformed maxDownloads was stored"
            );


            assert.equal(
                String(share.owner),
                String(user.id)
            );


            assert.equal(
                String(share.file),
                String(file.id)
            );


            assert.equal(
                typeof share.downloadCount,
                "number"
            );


            assert.ok(
                share.downloadCount >= 0
            );

        }

    }
);