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
    "MethodAbuseSecurity123!";

let user;
let token;
let file;
let share;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `method-abuse-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Method Abuse User",

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
    ownerId
) => {

    return File.create({

        originalName:
            "method-security.txt",

        storedName:
            `method-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/method-${Date.now()}.enc`,

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


const createShare = async (
    fileId,
    ownerId
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `method-token-${Date.now()}-${Math.random()
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
        await registerAndLogin();


    user =
        result.user;

    token =
        result.token;


    file =
        await createFile(
            user.id
        );


    share =
        await createShare(
            file.id,
            user.id
        );

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. GET CANNOT DELETE
   ========================================================= */

test(
    "GET cannot delete a file",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                file.id
            )
        );

    }
);


/* =========================================================
   2. POST CANNOT DELETE
   ========================================================= */

test(
    "POST cannot delete a file",
    async () => {

        const response =
            await request(app)
                .post(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                file.id
            )
        );

    }
);


/* =========================================================
   3. PUT CANNOT DELETE
   ========================================================= */

test(
    "PUT cannot delete a file",
    async () => {

        const response =
            await request(app)
                .put(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                file.id
            )
        );

    }
);


/* =========================================================
   4. PATCH CANNOT DELETE
   ========================================================= */

test(
    "PATCH cannot delete a file",
    async () => {

        const response =
            await request(app)
                .patch(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                file.id
            )
        );

    }
);


/* =========================================================
   5. GET CANNOT REVOKE SHARE
   ========================================================= */

test(
    "GET cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
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
   6. POST CANNOT REVOKE SHARE
   ========================================================= */

test(
    "POST cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .post(
                    `/api/share/${share.id}/revoke`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            200
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
   7. PUT CANNOT REVOKE SHARE
   ========================================================= */

test(
    "PUT cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .put(
                    `/api/share/${share.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    isRevoked:
                        true
                });


        assert.notEqual(
            response.status,
            200
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
   8. PATCH CANNOT REVOKE SHARE
   ========================================================= */

test(
    "PATCH cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .patch(
                    `/api/share/${share.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    isRevoked:
                        true
                });


        assert.notEqual(
            response.status,
            200
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
   9. OPTIONS CANNOT CHANGE FILE STATE
   ========================================================= */

test(
    "OPTIONS request cannot modify file state",
    async () => {

        const beforeFile =
            await File.findById(
                file.id
            );


        const response =
            await request(app)
                .options(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            500
        );


        const afterFile =
            await File.findById(
                file.id
            );


        assert.ok(
            afterFile
        );


        assert.equal(
            String(afterFile.owner),
            String(beforeFile.owner)
        );

    }
);


/* =========================================================
   10. HEAD CANNOT TRIGGER STATE CHANGE
   ========================================================= */

test(
    "HEAD request cannot trigger file deletion",
    async () => {

        const response =
            await request(app)
                .head(
                    `/api/files/${file.id}`
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
            await File.findById(
                file.id
            ),
            "HEAD request changed file state"
        );

    }
);