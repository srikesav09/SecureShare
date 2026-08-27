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

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD = "QuotaSecurity123!";

let user;
let token;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `quota-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Quota Security User",

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
        token:
            accessToken,

        user:
            databaseUser
    };
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

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. EMPTY FILE
   ========================================================= */

test(
    "empty upload is handled safely",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.alloc(0),
                    {
                        filename:
                            "empty.txt",

                        contentType:
                            "text/plain"
                    }
                );


        assert.notEqual(
            response.status,
            500,
            "Empty upload caused server error"
        );

    }
);


/* =========================================================
   2. SMALL VALID FILE
   ========================================================= */

test(
    "small valid upload remains accepted",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from(
                        "quota test"
                    ),
                    {
                        filename:
                            "quota.txt",

                        contentType:
                            "text/plain"
                    }
                );


        assert.equal(
            response.status,
            201,
            JSON.stringify(
                response.body
            )
        );

    }
);


/* =========================================================
   3. OVERSIZED UPLOAD
   ========================================================= */

test(
    "upload larger than configured limit is rejected",
    async () => {

        /*
         * Your upload middleware currently uses a
         * 10 MB file-size limit.
         *
         * Create a payload slightly larger than that.
         */
        const oversized =
            Buffer.alloc(
                10 * 1024 * 1024 + 1,
                "a"
            );


        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    oversized,
                    {
                        filename:
                            "oversized.txt",

                        contentType:
                            "text/plain"
                    }
                );


        assert.ok(
            [400, 413, 422].includes(
                response.status
            ),
            `Oversized upload was not rejected: ${response.status}`
        );

    }
);


/* =========================================================
   4. FILE SIZE FIELD CANNOT BE TRUSTED
   ========================================================= */

test(
    "client cannot override stored file size metadata",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    size:
                        Number.MAX_SAFE_INTEGER
                });


        assert.notEqual(
            response.status,
            201,
            "Client-controlled size created a file record"
        );


        const files =
            await File.find({
                owner:
                    user.id
            });


        assert.equal(
            files.length,
            0,
            "Malformed request created a file"
        );

    }
);


/* =========================================================
   5. MULTIPLE FILE FIELD
   ========================================================= */

test(
    "multiple uploaded files cannot bypass single-file limit",
    async () => {

        const requestBuilder =
            request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        requestBuilder.attach(
            "file",
            Buffer.from(
                "first file"
            ),
            {
                filename:
                    "first.txt",

                contentType:
                    "text/plain"
            }
        );


        requestBuilder.attach(
            "file",
            Buffer.from(
                "second file"
            ),
            {
                filename:
                    "second.txt",

                contentType:
                    "text/plain"
            }
        );


        const response =
            await requestBuilder;


        assert.notEqual(
            response.status,
            201,
            "Multiple file fields bypassed single-file upload limit"
        );

    }
);



/* =========================================================
   6. REPEATED SMALL UPLOADS
   ========================================================= */

test(
    "repeated uploads are handled safely",
    async () => {

        const responses = [];

        for (let i = 0; i < 10; i++) {

            const response =
                await request(app)
                    .post(
                        "/api/files/upload"
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    )
                    .attach(
                        "file",
                        Buffer.from(
                            `quota-test-${i}`
                        ),
                        {
                            filename:
                                `quota-${i}.txt`,

                            contentType:
                                "text/plain"
                        }
                    );

            responses.push(response);

            assert.notEqual(
                response.status,
                500,
                `Upload ${i + 1} caused a server error`
            );
        }


        /*
         * Every response must be a controlled application
         * response. A rate-limit response is valid, but it
         * is not required for this particular test because
         * limiter keying may differ by runtime configuration.
         */
        for (const response of responses) {

            assert.ok(
                response.status >= 200 &&
                response.status < 500,
                `Unexpected uncontrolled response: ${response.status}`
            );

        }

    }
);


/* =========================================================
   7. HUGE FILENAME
   ========================================================= */

test(
    "extremely large filename is rejected safely",
    async () => {

        const filename =
            `${"a".repeat(1000)}.txt`;


        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    Buffer.from(
                        "filename quota test"
                    ),
                    {
                        filename,

                        contentType:
                            "text/plain"
                    }
                );


        assert.notEqual(
            response.status,
            500,
            "Large filename caused server crash"
        );

    }
);


/* =========================================================
   8. MANY FORM FIELDS
   ========================================================= */

test(
    "large number of unrelated form fields does not create files",
    async () => {

        const payload = {};


        for (let i = 0; i < 1000; i++) {

            payload[
                `field${i}`
            ] =
                "x".repeat(100);

        }


        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send(
                    payload
                );


        assert.notEqual(
            response.status,
            500
        );


        const files =
            await File.find({
                owner:
                    user.id
            });


        assert.equal(
            files.length,
            0,
            "Form-field abuse created a file"
        );

    }
);


/* =========================================================
   9. FAKE STORAGE METADATA
   ========================================================= */

test(
    "client cannot directly submit storage metadata to create a file",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({

                    originalName:
                        "attacker.txt",

                    storedName:
                        "../../evil.txt",

                    s3Key:
                        "private/attacker-key",

                    size:
                        999999999,

                    owner:
                        "507f1f77bcf86cd799439011"

                });


        assert.notEqual(
            response.status,
            201,
            "Client-supplied storage metadata created a file"
        );


        const files =
            await File.find({
                owner:
                    user.id
            });


        assert.equal(
            files.length,
            0
        );

    }
);


/* =========================================================
   10. DATABASE SIZE INTEGRITY
   ========================================================= */

test(
    "stored file size reflects uploaded content",
    async () => {

        const content =
            Buffer.from(
                "Known content for size validation"
            );


        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .attach(
                    "file",
                    content,
                    {
                        filename:
                            "size-check.txt",

                        contentType:
                            "text/plain"
                    }
                );


        assert.equal(
            response.status,
            201,
            JSON.stringify(
                response.body
            )
        );


        const storedFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            storedFile,
            "Database record was not created"
        );


        /*
         * The stored size must represent the actual
         * upload, not attacker-controlled metadata.
         */
        assert.equal(
            storedFile.size,
            content.length,
            "Stored size does not match uploaded content"
        );

    }
);