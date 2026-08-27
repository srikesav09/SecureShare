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


const PASSWORD = "PublicShareSecurity123!";

let user;
let token;
let file;
let share;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `public-share-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Public Share Security User",

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


const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "confidential-report.pdf",

        storedName:
            `private-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.pdf`,

        mimeType:
            "application/pdf",

        size:
            1234,

        s3Key:
            `private/confidential-${Date.now()}.enc`,

        owner:
            ownerId,

        encrypted:
            true,

        iv:
            "super-secret-iv",

        hash:
            "private-file-hash-secret"

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
            `public-security-${Date.now()}-${Math.random()
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
   1. INVALID TOKEN
   ========================================================= */

test(
    "invalid public share token is handled safely",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/share/this-is-not-a-real-token"
                );


        assert.notEqual(
            response.status,
            500,
            "Invalid public token caused server error"
        );

    }
);


/* =========================================================
   2. EMPTY TOKEN
   ========================================================= */

test(
    "empty public share token does not expose file data",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/share/"
                );


        assert.notEqual(
            response.status,
            200,
            "Empty share token returned successful data"
        );

    }
);


/* =========================================================
   3. INTERNAL S3 KEY MUST NOT LEAK
   ========================================================= */

test(
    "public share response does not expose S3 key",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                file.s3Key
            ),
            false,
            "S3 key leaked through public share response"
        );

    }
);


/* =========================================================
   4. ENCRYPTION IV MUST NOT LEAK
   ========================================================= */

test(
    "public share response does not expose encryption IV",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                file.iv
            ),
            false,
            "Encryption IV leaked through public share response"
        );

    }
);


/* =========================================================
   5. FILE HASH MUST NOT LEAK
   ========================================================= */

test(
    "public share response does not expose internal file hash",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                file.hash
            ),
            false,
            "Internal file hash leaked"
        );

    }
);


/* =========================================================
   6. OWNER ID MUST NOT BE EXPOSED UNNECESSARILY
   ========================================================= */

test(
    "public share response does not expose internal owner identifier",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${share.token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        /*
         * Public endpoints should not expose raw Mongo
         * ownership identifiers unless specifically required.
         */
        assert.equal(
            body.includes(
                String(user.id)
            ),
            false,
            "Internal owner ID leaked through public share"
        );

    }
);


/* =========================================================
   7. PASSWORD HASH MUST NOT LEAK
   ========================================================= */

test(
    "password-protected share does not expose password hash",
    async () => {

        const bcrypt =
            await import("bcrypt");


        const passwordHash =
            await bcrypt.hash(
                "ProtectedPassword123!",
                10
            );


        const protectedShare =
            await createShare(
                file.id,
                user.id,
                {
                    passwordHash
                }
            );


        const response =
            await request(app)
                .get(
                    `/api/share/${protectedShare.token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                passwordHash
            ),
            false,
            "Share password hash leaked"
        );


        assert.equal(
            body.toLowerCase().includes(
                "passwordhash"
            ),
            false,
            "passwordHash field leaked"
        );

    }
);


/* =========================================================
   8. REVOKED SHARE
   ========================================================= */

test(
    "revoked public share does not expose file data",
    async () => {

        const revokedShare =
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
                    `/api/share/${revokedShare.token}`
                );


        assert.notEqual(
            response.status,
            200,
            "Revoked share returned successful file access"
        );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                file.s3Key
            ),
            false
        );

    }
);


/* =========================================================
   9. EXPIRED SHARE
   ========================================================= */

test(
    "expired public share does not expose file data",
    async () => {

        const expiredShare =
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
                    `/api/share/${expiredShare.token}`
                );


        assert.notEqual(
            response.status,
            200,
            "Expired share returned successful file access"
        );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                file.s3Key
            ),
            false
        );

    }
);


/* =========================================================
   10. INTERNAL ERROR INFORMATION
   ========================================================= */

test(
    "public share errors do not expose internal server information",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/not-a-real-token-${Date.now()}`
                );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "node_modules"
            ),
            false
        );


        assert.equal(
            body.includes(
                "mongoose"
            ),
            false
        );


        assert.equal(
            body.includes(
                "stack"
            ),
            false
        );


        assert.equal(
            body.includes(
                "src/controllers"
            ),
            false
        );


        assert.equal(
            body.includes(
                process.cwd().toLowerCase()
            ),
            false
        );

    }
);