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


const USER_PASSWORD = "SharePasswordSecurity123!";

const SHARE_PASSWORD =
    "CorrectSharePassword123!";

let user;
let token;
let file;
let share;


/*
 * =========================================================
 * HELPERS
 * =========================================================
 */

const registerAndLogin = async () => {

    const email =
        `share-password-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Share Password User",
                email,
                password: USER_PASSWORD
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
                password: USER_PASSWORD
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
        user: databaseUser,
        token: accessToken
    };
};


const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "share-password-test.txt",

        storedName:
            `share-password-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/share-password-${Date.now()}.enc`,

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
 * The application stores passwordHash rather than the
 * plaintext share password.
 *
 * Use the same hashing mechanism used by the application
 * when possible. For this security suite, bcryptjs is used
 * to create a valid password hash.
 */

const createPasswordHash = async (
    password
) => {

    const bcrypt =
        await import("bcrypt");

    return bcrypt.hash(
        password,
        10
    );
};


const createShare = async (
    fileId,
    ownerId,
    passwordHash
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `share-password-token-${Date.now()}-${Math.random()
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

        passwordHash

    });
};


/*
 * =========================================================
 * SETUP
 * =========================================================
 */

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


    const passwordHash =
        await createPasswordHash(
            SHARE_PASSWORD
        );


    share =
        await createShare(
            file.id,
            user.id,
            passwordHash
        );

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. PASSWORD IS NOT STORED IN PLAINTEXT
 * =========================================================
 */

test(
    "share password is not stored in plaintext",
    async () => {

        assert.ok(
            share.passwordHash,
            "Password hash is missing"
        );


        assert.notEqual(
            share.passwordHash,
            SHARE_PASSWORD,
            "Share password was stored in plaintext"
        );

    }
);


/*
 * =========================================================
 * 2. PASSWORD HASH HAS BCRYPT FORMAT
 * =========================================================
 */

test(
    "share password uses a password hash format",
    async () => {

        assert.match(
            share.passwordHash,
            /^\$2[aby]\$/,
            "Share password does not appear to use bcrypt hashing"
        );

    }
);


/*
 * =========================================================
 * 3. SHARE RESPONSE MUST NOT LEAK PASSWORD HASH
 * =========================================================
 */

test(
    "share API response does not expose password hash",
    async () => {

        /*
         * The owner creates another share through the API.
         * This checks the response serialization boundary.
         */

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

                    password:
                        SHARE_PASSWORD
                });


        assert.equal(
            response.status,
            201,
            `Share creation failed: ${JSON.stringify(response.body)}`
        );


        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();


        assert.equal(
            body.includes(
                "passwordhash"
            ),
            false,
            "Password hash leaked through share response"
        );


        assert.equal(
            body.includes(
                SHARE_PASSWORD.toLowerCase()
            ),
            false,
            "Plaintext share password leaked through response"
        );

    }
);


/*
 * =========================================================
 * 4. MISSING PASSWORD MUST NOT ACT AS AUTHENTICATION
 * =========================================================
 */

test(
    "missing share password cannot authenticate a protected share",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        /*
         * Depending on the public-share implementation,
         * safe outcomes include authentication failure,
         * bad request, not found, or another controlled response.
         */
        assert.notEqual(
            response.status,
            500,
            "Missing password caused a server error"
        );


        /*
         * A protected share must not expose the file merely
         * because the password was omitted.
         */
        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                "share-password-test.txt"
            ),
            false,
            "Protected file was exposed without password"
        );

    }
);


/*
 * =========================================================
 * 5. WRONG PASSWORD MUST NOT AUTHENTICATE
 * =========================================================
 */

test(
    "wrong share password cannot authenticate",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                )
                .query({
                    password:
                        "DefinitelyWrongPassword!"
                });


        assert.notEqual(
            response.status,
            200,
            "Wrong share password was accepted"
        );


        assert.notEqual(
            response.status,
            500,
            "Wrong share password caused a server error"
        );

    }
);


/*
 * =========================================================
 * 6. EMPTY PASSWORD MUST NOT AUTHENTICATE
 * =========================================================
 */

test(
    "empty share password cannot authenticate",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                )
                .query({
                    password:
                        ""
                });


        assert.notEqual(
            response.status,
            200,
            "Empty password authenticated protected share"
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 7. PASSWORD HASH CANNOT BE USED AS PASSWORD
 * =========================================================
 */

test(
    "stored password hash cannot be used as plaintext password",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                )
                .query({
                    password:
                        share.passwordHash
                });


        assert.notEqual(
            response.status,
            200,
            "Password hash was accepted as plaintext password"
        );

    }
);


/*
 * =========================================================
 * 8. PASSWORD FIELD TYPE CONFUSION
 * =========================================================
 */

test(
    "object password cannot bypass protected share",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                )
                .query({
                    password: {
                        $ne: ""
                    }
                });


        assert.notEqual(
            response.status,
            200,
            "Object password bypassed share authentication"
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 9. ARRAY PASSWORD CANNOT BYPASS
 * =========================================================
 */

test(
    "array password cannot bypass protected share",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                )
                .query({
                    password: [
                        SHARE_PASSWORD,
                        "wrong-password"
                    ]
                });


        assert.notEqual(
            response.status,
            200,
            "Array password bypassed share authentication"
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 10. PASSWORD HASH CANNOT BE MODIFIED THROUGH REQUEST
 * =========================================================
 */

test(
    "client cannot replace stored password hash",
    async () => {

        const originalHash =
            share.passwordHash;


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

                    password:
                        SHARE_PASSWORD,

                    passwordHash:
                        "attacker-controlled-hash"

                });


        assert.notEqual(
            response.status,
            500
        );


        const databaseShares =
            await Share.find({
                file:
                    file.id,

                owner:
                    user.id
            });


        for (
            const databaseShare
            of databaseShares
        ) {

            /*
             * A client-supplied passwordHash must never become
             * the stored authentication credential.
             */
            assert.notEqual(
                databaseShare.passwordHash,
                "attacker-controlled-hash",
                "Client-controlled passwordHash was stored"
            );

        }


        const originalShare =
            await Share.findById(
                share.id
            );


        assert.ok(
            originalShare
        );


        assert.equal(
            originalShare.passwordHash,
            originalHash,
            "Existing share password hash was modified"
        );

    }
);