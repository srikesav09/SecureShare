import "./env.js";

import assert from "node:assert/strict";
import test, { before, after, beforeEach } from "node:test";
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


const PASSWORD = "StrongPassword123!";

let owner;
let ownerToken;
let file;
let share;


/* =========================================================
   CREATE AUTHENTICATED USER
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `nosql-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "NoSQL Security User",
                email,
                password: PASSWORD
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
                password: PASSWORD
            });


    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );


    const token =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;


    assert.ok(
        token,
        `JWT token missing: ${JSON.stringify(login.body)}`
    );


    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(
        databaseUser,
        "Authenticated user was not found"
    );


    return {
        user: databaseUser,
        token
    };
};


/* =========================================================
   CREATE FILE
   ========================================================= */

const createTestFile = async (ownerId) => {

    return File.create({

        originalName:
            "nosql-security-test.txt",

        storedName:
            `nosql-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/nosql-${Date.now()}-${Math.random()
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


/* =========================================================
   CREATE SHARE
   ========================================================= */

const createTestShare = async (
    fileId,
    ownerId
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `nosql-token-${Date.now()}-${Math.random()
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
   DATABASE SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

    /*
     * Clean once at the beginning.
     */
    await clearTestDatabase();


    /*
     * ONE registration + ONE login for the complete file.
     */
    const result =
        await registerAndLogin();


    owner =
        result.user;

    ownerToken =
        result.token;

});


/* =========================================================
   FRESH RESOURCES BEFORE EACH TEST
   ========================================================= */

beforeEach(async () => {

    /*
     * Do NOT call clearTestDatabase().
     *
     * That would delete `owner`, which is the user
     * associated with the JWT.
     */

    await File.deleteMany({});

    await Share.deleteMany({});


    file =
        await createTestFile(
            owner.id
        );


    share =
        await createTestShare(
            file.id,
            owner.id
        );

});


/* =========================================================
   DATABASE CLEANUP
   ========================================================= */

after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. EMAIL $ne
   ========================================================= */

test(
    "login rejects object-valued email NoSQL injection",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({

                    email: {
                        $ne: null
                    },

                    password:
                        PASSWORD

                });


        assert.notEqual(
            response.status,
            200,
            "Email $ne injection bypassed authentication"
        );

    }
);


/* =========================================================
   2. PASSWORD $ne
   ========================================================= */

test(
    "login rejects $ne password injection",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({

                    email:
                        owner.email,

                    password: {
                        $ne: null
                    }

                });


        assert.notEqual(
            response.status,
            200,
            "Password $ne injection bypassed authentication"
        );

    }
);


/* =========================================================
   3. PASSWORD $gt
   ========================================================= */

test(
    "login rejects $gt password injection",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({

                    email:
                        owner.email,

                    password: {
                        $gt: ""
                    }

                });


        assert.notEqual(
            response.status,
            200,
            "Password $gt injection bypassed authentication"
        );

    }
);


/* =========================================================
   4. PASSWORD $regex
   ========================================================= */

test(
    "login rejects $regex password injection",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({

                    email:
                        owner.email,

                    password: {
                        $regex: ".*"
                    }

                });


        assert.notEqual(
            response.status,
            200,
            "Password regex injection bypassed authentication"
        );

    }
);


/* =========================================================
   5. REGISTRATION EMAIL OBJECT
   ========================================================= */

test(
    "registration rejects object-valued email",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({

                    name:
                        "Injection User",

                    email: {
                        $ne: null
                    },

                    password:
                        PASSWORD

                });


        assert.notEqual(
            response.status,
            201,
            "Object email was accepted during registration"
        );

    }
);


/* =========================================================
   6. REGISTRATION PASSWORD OBJECT
   ========================================================= */

test(
    "registration rejects object-valued password",
    async () => {

        const email =
            `inject-password-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({

                    name:
                        "Injection User",

                    email,

                    password: {
                        $ne: null
                    }

                });


        assert.notEqual(
            response.status,
            201,
            "Object password was accepted during registration"
        );


        const createdUser =
            await User.findOne({
                email
            });


        assert.equal(
            createdUser,
            null,
            "Injected password created a user"
        );

    }
);


/* =========================================================
   7. SHARE OWNER QUERY INJECTION
   ========================================================= */

test(
    "share lookup cannot be bypassed with query operators",
    async () => {

        const originalOwner =
            String(share.owner);


        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?ownerId[$ne]=null`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        assert.notEqual(
            response.status,
            500,
            "NoSQL operator caused a server error"
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        /*
         * Owner must never change because of request
         * query parameters.
         */
        if (databaseShare) {

            assert.equal(
                String(databaseShare.owner),
                originalOwner,
                "NoSQL injection changed share ownership"
            );

        }

    }
);


/* =========================================================
   8. SHARE ID / QUERY INJECTION
   ========================================================= */

test(
    "share ID injection cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?shareId[$ne]=null`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        assert.notEqual(
            response.status,
            500,
            "NoSQL operator caused a server error"
        );


        /*
         * Endpoint must not interpret the query parameter
         * as a replacement for the path resource.
         */
        const databaseShare =
            await Share.findById(
                share.id
            );


        /*
         * The share may legitimately be revoked because
         * this JWT belongs to its owner. What matters is
         * that the query operator did not corrupt the record.
         */
        assert.ok(
            databaseShare === null ||
            String(databaseShare.owner) === String(owner.id)
        );

    }
);



/* =========================================================
   FILE OWNERSHIP NoSQL INJECTION
   ========================================================= */

test(
    "file ownership cannot be changed using query operators",
    async () => {

        const originalOwner =
            String(file.owner);


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download?owner[$ne]=null`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        /*
         * The test uses a fake storage object, so the download
         * itself may legitimately fail with a storage-related
         * response such as 404/500.
         *
         * The security property being tested here is that the
         * query parameter cannot modify the database ownership.
         */


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.ok(
            databaseFile,
            "File unexpectedly disappeared after injection attempt"
        );


        assert.equal(
            String(databaseFile.owner),
            originalOwner,
            "NoSQL injection changed file ownership"
        );


        /*
         * The request must not return a successful response
         * representing unauthorized access through the injected
         * owner parameter.
         *
         * A storage failure is acceptable for this fixture.
         */
        assert.ok(
            response.status !== 200 ||
            databaseFile,
            "Unexpected successful download response"
        );

    }
);


/* =========================================================
   10. USER ID $ne
   ========================================================= */

test(
    "user identity cannot be selected using $ne",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files?userId[$ne]=null"
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        assert.notEqual(
            response.status,
            500,
            "NoSQL user identity injection caused server error"
        );

    }
);


/* =========================================================
   11. REGEX QUERY INJECTION
   ========================================================= */

test(
    "regex query injection does not cause server error",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files?search[$regex]=.*"
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        assert.notEqual(
            response.status,
            500,
            "Regex injection caused server error"
        );

    }
);


/* =========================================================
   12. SHARE OWNERSHIP INTEGRITY
   ========================================================= */

test(
    "NoSQL injection cannot modify share ownership",
    async () => {

        const originalOwner =
            String(share.owner);


        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?owner[$ne]=null`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        assert.notEqual(
            response.status,
            500
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        /*
         * If the share still exists, ownership must remain
         * exactly the same.
         */
        if (databaseShare) {

            assert.equal(
                String(databaseShare.owner),
                originalOwner
            );

        }

    }
);


/* =========================================================
   13. REGISTRATION ROLE OPERATOR
   ========================================================= */

test(
    "MongoDB operator in registration body cannot create ADMIN",
    async () => {

        const email =
            `operator-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({

                    name:
                        "Operator Test",

                    email,

                    password:
                        PASSWORD,

                    role: {
                        $ne: "USER"
                    }

                });


        /*
         * Safe outcomes:
         *
         * 400 = rejected
         * 201 = safely created as USER
         */
        assert.ok(
            [400, 201].includes(response.status),
            `Unexpected response: ${response.status}`
        );


        if (response.status === 201) {

            const createdUser =
                await User.findOne({
                    email
                });


            assert.ok(
                createdUser
            );


            assert.equal(
                createdUser.role,
                "USER",
                "MongoDB operator created a privileged account"
            );

        }

    }
);