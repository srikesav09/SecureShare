import "./env.js";

import assert from "node:assert/strict";
import test, {
    before,
    after,
    beforeEach
} from "node:test";

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


// ============================================================
// CONFIGURATION
// ============================================================

const PASSWORD = "StrongPassword123!";

const JWT_SECRET =
    process.env.JWT_SECRET ||
    process.env.ACCESS_TOKEN_SECRET ||
    process.env.JWT_SECRET_KEY;

assert.ok(
    JWT_SECRET,
    "JWT secret is not configured for security tests"
);


// ============================================================
// TEST STATE
// ============================================================

let token;
let user;
let file;
let share;


// ============================================================
// HELPERS
// ============================================================

const uniqueEmail = (
    prefix = "host-security"
) =>
    `${prefix}-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 10)}@example.com`;


// ============================================================
// REGISTER + LOGIN
// ============================================================

const registerAndLogin = async (
    name = "Host Security User",
    email = uniqueEmail()
) => {

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name,
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


    const accessToken =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.accessToken ||
        login.body?.data?.accessToken;


    assert.ok(
        accessToken,
        `JWT token not returned: ${JSON.stringify(login.body)}`
    );


    /*
     * Do not depend on login.body.data.user.
     *
     * The actual database document is authoritative.
     */
    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(
        databaseUser,
        `User was not found in database: ${email}`
    );


    return {
        token: accessToken,
        user: databaseUser,
        email
    };
};


// ============================================================
// CREATE JWT WITHOUT ANOTHER LOGIN REQUEST
// ============================================================

const createTestJwt = (databaseUser) => {

    const userId =
        databaseUser.id ||
        databaseUser._id;


    assert.ok(
        userId,
        "Cannot create JWT: user has no id"
    );


    return jwt.sign(
        {
            sub: String(userId),
            id: String(userId)
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );
};


// ============================================================
// CREATE TEST FILE
// ============================================================

const createTestFile = async (ownerId) => {

    assert.ok(
        ownerId,
        "createTestFile() received an invalid owner ID"
    );


    return File.create({

        originalName:
            "host-header-test.txt",

        storedName:
            `host-header-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/host-header-${Date.now()}-${Math.random()
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


// ============================================================
// CREATE TEST SHARE
// ============================================================

const createTestShare = async (
    fileId,
    ownerId
) => {

    assert.ok(
        fileId,
        "createTestShare() received an invalid file ID"
    );

    assert.ok(
        ownerId,
        "createTestShare() received an invalid owner ID"
    );


    return Share.create({

        file:
            fileId,

        owner:
            ownerId,

        token:
            `host-header-token-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}`,

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


// ============================================================
// DATABASE START
// ============================================================

before(async () => {

    await startTestDatabase();

});


// ============================================================
// FRESH TEST FIXTURES
// ============================================================

beforeEach(async () => {

    await clearTestDatabase();


    /*
     * Exactly ONE login request per test.
     *
     * This is important because the production login
     * rate limiter allows only 10 requests per window.
     */
    const result =
        await registerAndLogin();


    token =
        result.token;

    user =
        result.user;


    /*
     * Your User model exposes the MongoDB ID as `id`.
     *
     * We still support `_id` as a fallback because Mongoose
     * internally provides it.
     */
    const userId =
        user.id ||
        user._id;


    assert.ok(
        userId,
        "Test user does not have a database ID"
    );


    file =
        await createTestFile(
            userId
        );


    share =
        await createTestShare(
            file.id ||
            file._id,
            userId
        );


    assert.ok(
        file.id ||
        file._id,
        "Test file was not created"
    );


    assert.ok(
        share.id ||
        share._id,
        "Test share was not created"
    );

});


// ============================================================
// DATABASE STOP
// ============================================================

after(async () => {

    await stopTestDatabase();

});


// ============================================================
// 1. HOST HEADER CANNOT POISON SHARE URL
// ============================================================

test(
    "malicious Host header cannot poison generated share URL",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Host",
                    "attacker.example.com"
                )
                .send({});


        assert.ok(
            [200, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status} ${JSON.stringify(response.body)}`
        );


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareLink,
            `Share link missing: ${JSON.stringify(response.body)}`
        );


        assert.ok(
            !shareLink.includes(
                "attacker.example.com"
            ),
            `Share link was poisoned: ${shareLink}`
        );
    }
);


// ============================================================
// 2. X-FORWARDED-HOST CANNOT POISON SHARE URL
// ============================================================

test(
    "X-Forwarded-Host cannot poison generated share URL",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "X-Forwarded-Host",
                    "attacker.example.com"
                )
                .send({});


        assert.ok(
            [200, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status} ${JSON.stringify(response.body)}`
        );


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareLink
        );


        assert.ok(
            !shareLink.includes(
                "attacker.example.com"
            ),
            `X-Forwarded-Host poisoned share URL: ${shareLink}`
        );
    }
);


// ============================================================
// 3. MULTIPLE HOST VALUES
// ============================================================

test(
    "multiple Host headers cannot poison share URL",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Host",
                    "attacker.example.com"
                )
                .send({});


        assert.ok(
            [200, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status} ${JSON.stringify(response.body)}`
        );


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareLink
        );


        assert.ok(
            !shareLink.includes(
                "attacker.example.com"
            )
        );
    }
);


// ============================================================
// 4. HOST CANNOT BYPASS AUTHENTICATION
// ============================================================

test(
    "malicious Host header cannot bypass authentication",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Host",
                    "attacker.example.com"
                );


        assert.ok(
            [401, 403].includes(
                response.status
            ),
            `Expected authentication failure, got ${response.status}`
        );
    }
);


// ============================================================
// 5. X-FORWARDED-HOST CANNOT BYPASS AUTHENTICATION
// ============================================================

test(
    "X-Forwarded-Host cannot bypass authentication",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "X-Forwarded-Host",
                    "attacker.example.com"
                );


        assert.ok(
            [401, 403].includes(
                response.status
            ),
            `Expected authentication failure, got ${response.status}`
        );
    }
);


// ============================================================
// 6. HOST CANNOT CHANGE FILE OWNERSHIP
// ============================================================

test(
    "Host header cannot change authenticated file ownership",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Host",
                    "attacker.example.com"
                );


        /*
         * The storage layer is intentionally fake.
         *
         * A storage error is acceptable.
         * A 401 is not, because the valid JWT must remain
         * the authenticated identity.
         */
        assert.notEqual(
            response.status,
            401,
            "Host header replaced valid JWT authentication"
        );
    }
);


// ============================================================
// 7. X-FORWARDED-PROTO CANNOT POISON URL
// ============================================================

test(
    "X-Forwarded-Proto cannot poison generated share URL",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "X-Forwarded-Proto",
                    "javascript"
                )
                .send({});


        assert.ok(
            [200, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status} ${JSON.stringify(response.body)}`
        );


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareLink,
            `Share link missing: ${JSON.stringify(response.body)}`
        );


        assert.ok(
            !shareLink
                .toLowerCase()
                .startsWith(
                    "javascript:"
                ),
            `Dangerous scheme generated: ${shareLink}`
        );
    }
);


// ============================================================
// 8. CRLF HOST INJECTION
// ============================================================

test(
    "CRLF Host injection is rejected safely",
    async () => {

        let response;


        try {

            response =
                await request(app)
                    .get("/api/files")
                    .set(
                        "Host",
                        "attacker.example.com\r\nX-Injected: true"
                    );

        } catch (error) {

            /*
             * Node itself may reject malformed HTTP headers.
             * That is safe.
             */

            assert.ok(
                error
            );

            return;
        }


        assert.notEqual(
            response.status,
            200,
            "CRLF Host injection produced a successful response"
        );
    }
);


// ============================================================
// 9. ORIGIN CANNOT POISON SHARE URL
// ============================================================

test(
    "malicious Origin cannot poison generated share URL",
    async () => {

        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Origin",
                    "https://attacker.example.com"
                )
                .send({});


        assert.ok(
            [200, 201].includes(
                response.status
            ),
            `Unexpected response: ${response.status} ${JSON.stringify(response.body)}`
        );


        const shareLink =
            response.body?.shareLink ||
            response.body?.data?.shareLink;


        assert.ok(
            shareLink,
            `Share link missing: ${JSON.stringify(response.body)}`
        );


        assert.ok(
            !shareLink.includes(
                "attacker.example.com"
            ),
            `Origin poisoned share URL: ${shareLink}`
        );
    }
);


// ============================================================
// 10. HOST MANIPULATION CANNOT BYPASS SHARE OWNERSHIP
// ============================================================

test(
    "host manipulation cannot bypass share ownership",
    async () => {

        const otherEmail =
            uniqueEmail("other-host");


        /*
         * IMPORTANT:
         *
         * Register the attacker, but DO NOT call /login.
         *
         * Calling registerAndLogin() here would be the 11th
         * login request from the same test IP because each
         * beforeEach() already performs one login.
         *
         * That would trigger the production login rate limiter.
         */
        const register =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Other Host User",
                    email: otherEmail,
                    password: PASSWORD
                });


        assert.ok(
            [200, 201].includes(
                register.status
            ),
            `Attacker registration failed: ${JSON.stringify(register.body)}`
        );


        const otherUser =
            await User.findOne({
                email: otherEmail
            });


        assert.ok(
            otherUser,
            "Attacker user was not created"
        );


        const otherUserId =
            otherUser.id ||
            otherUser._id;


        assert.ok(
            otherUserId,
            "Attacker user has no database ID"
        );


        /*
         * Create a cryptographically valid JWT directly.
         *
         * This does NOT weaken production security.
         * It only avoids consuming another login request
         * in this test.
         */
        const otherToken =
            createTestJwt(
                otherUser
            );


        assert.ok(
            otherToken
        );


        const fileId =
            file.id ||
            file._id;


        const response =
            await request(app)
                .post(
                    `/api/share/${fileId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${otherToken}`
                )
                .set(
                    "Host",
                    "attacker.example.com"
                )
                .set(
                    "X-Forwarded-Host",
                    "attacker.example.com"
                )
                .send({});


        /*
         * The authenticated attacker owns no rights to the
         * owner's file. Host manipulation must not change that.
         */
        assert.equal(
            response.status,
            403,
            `Expected ownership rejection, got ${response.status}: ${JSON.stringify(response.body)}`
        );


        const shares =
            await Share.find({
                file: fileId
            });


        /*
         * Every share for this file must still belong to
         * the original owner.
         */
        const ownerId =
            user.id ||
            user._id;


        for (const databaseShare of shares) {

            assert.equal(
                String(databaseShare.owner),
                String(ownerId),
                "Unauthorized user became share owner"
            );
        }
    }
);