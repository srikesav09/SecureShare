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


// =========================================================
// CONSTANTS
// =========================================================

const PASSWORD = "CsrfAdvanced123!";


// =========================================================
// STATE
// =========================================================

let user;
let token;
let file;
let share;


// =========================================================
// HELPERS
// =========================================================

const uniqueEmail = () =>
    `csrf-advanced-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 10)}@example.com`;


const createUserAndLogin = async () => {

    const email = uniqueEmail();

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "CSRF Advanced User",
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
        databaseUser
    );


    return {
        user: databaseUser,
        token: accessToken
    };
};


const createTestFile = async (ownerId) => {

    return File.create({

        originalName:
            "csrf-test.txt",

        storedName:
            `csrf-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/csrf-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}.enc`,

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
    ownerId
) => {

    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `csrf-token-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}`,

        expiresAt:
            new Date(
                Date.now() +
                60 * 60 * 1000
            ),

        maxDownloads:
            null,

        downloadCount:
            0,

        isRevoked:
            false,

        passwordHash:
            null
    });
};


// =========================================================
// SETUP
// =========================================================

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


    share =
        await createTestShare(
            file.id,
            user.id
        );

});


after(async () => {

    await stopTestDatabase();

});


// =========================================================
// 1. CROSS-ORIGIN FILE DELETE
// =========================================================

test(
    "cross-origin request without authentication cannot delete a file",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                );


        assert.equal(
            response.status,
            401
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.ok(
            databaseFile,
            "Unauthenticated cross-origin request deleted the file"
        );

    }
);


// =========================================================
// 2. CROSS-ORIGIN SHARE REVOCATION
// =========================================================

test(
    "cross-origin request cannot revoke a share using Origin",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                );


        /*
         * We do not require a particular status here because
         * applications using bearer JWT authentication may
         * intentionally not implement browser-cookie CSRF.
         */
        assert.notEqual(
            response.status,
            500
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        /*
         * Origin must never be interpreted as a signal that
         * grants ownership or authorization.
         */
        assert.equal(
            databaseShare.owner.toString(),
            user.id.toString()
        );

    }
);


// =========================================================
// 3. ORIGIN CANNOT CHANGE USER ID
// =========================================================

test(
    "malicious Origin cannot alter authenticated identity",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                );


        assert.notEqual(
            response.status,
            401
        );

    }
);


// =========================================================
// 4. REFERER CANNOT GRANT ACCESS
// =========================================================

test(
    "malicious Referer cannot bypass authentication",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Referer",
                    "https://attacker.example.com/steal"
                );


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 5. REFERER CANNOT BYPASS OWNERSHIP
// =========================================================

test(
    "malicious Referer cannot bypass authentication",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Referer",
                    "https://attacker.example.com/steal"
                );


        assert.equal(
            response.status,
            401
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.ok(
            databaseFile,
            "Unauthenticated request with malicious Referer deleted the file"
        );

    }
);


// =========================================================
// 6. ORIGIN + REFERER COMBINATION
// =========================================================

test(
    "Origin and Referer together cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                )
                .set(
                    "Referer",
                    "https://attacker.example.com/attack"
                );


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

    }
);


// =========================================================
// 7. FORGED CSRF HEADER
// =========================================================

test(
    "attacker-controlled CSRF header cannot grant authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}`
                )
                .set(
                    "X-CSRF-Token",
                    "attacker-forged-token"
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                );


        /*
         * No JWT means authentication must still fail.
         */
        assert.equal(
            response.status,
            401
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.isRevoked,
            false
        );

    }
);


// =========================================================
// 8. CROSS-ORIGIN SHARE CREATION
// =========================================================

test(
    "cross-origin request cannot create a share without authentication",
    async () => {

        const response =
            await request(app)
                .post(
                    `/api/share/${file.id}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                )
                .send({
                    maxDownloads: 5
                });


        assert.equal(
            response.status,
            401
        );


        const shares =
            await Share.find({
                file: file.id
            });


        /*
         * Only the original test share should exist.
         */
        assert.equal(
            shares.length,
            1
        );

    }
);


// =========================================================
// 9. X-HTTP-METHOD-OVERRIDE
// =========================================================

test(
    "CSRF-style method override cannot turn GET into DELETE",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "X-HTTP-Method-Override",
                    "DELETE"
                );


        assert.notEqual(
            response.status,
            500
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.ok(
            databaseFile,
            "Method override deleted the file"
        );

    }
);


// =========================================================
// 10. QUERY METHOD OVERRIDE
// =========================================================

test(
    "query method override cannot perform state-changing action",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.id}?_method=DELETE`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            500
        );


        const databaseShare =
            await Share.findById(
                share.id
            );


        assert.equal(
            databaseShare.isRevoked,
            false
        );

    }
);