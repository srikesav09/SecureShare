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


const PASSWORD =
    "EncryptionFailure123!";

let user;
let token;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `encryption-failure-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Encryption Failure User",

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
        "JWT token was not returned"
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


const upload = (
    filename,
    content,
    contentType = "text/plain"
) => {

    return request(app)
        .post(
            "/api/files/upload"
        )
        .set(
            "Authorization",
            `Bearer ${token}`
        )
        .attach(
            "file",
            Buffer.from(content),
            {
                filename,
                contentType
            }
        );
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
   1. ENCRYPTION KEY MUST NOT APPEAR IN UPLOAD RESPONSE
   ========================================================= */

test(
    "upload response does not expose encryption key",
    async () => {

        const response =
            await upload(
                "encryption-test.txt",
                "secure content",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();


        const configuredKey =
            process.env.ENCRYPTION_KEY ||
            "";


        if (configuredKey) {

            assert.equal(
                body.includes(
                    configuredKey.toLowerCase()
                ),
                false,
                "Encryption key leaked through upload response"
            );

        }


        assert.equal(
            body.includes(
                "encryption_key"
            ),
            false
        );


        assert.equal(
            body.includes(
                "encryptionkey"
            ),
            false
        );

    }
);


/* =========================================================
   2. UPLOAD RESPONSE MUST NOT EXPOSE IV
   ========================================================= */

test(
    "upload response does not expose encryption IV",
    async () => {

        const response =
            await upload(
                "iv-test.txt",
                "IV security test",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();


        assert.equal(
            body.includes(
                "\"iv\""
            ),
            false,
            "Encryption IV leaked through upload response"
        );

    }
);


/* =========================================================
   3. DATABASE ENCRYPTION METADATA EXISTS
   ========================================================= */

test(
    "successful encrypted upload stores encryption metadata",
    async () => {

        const response =
            await upload(
                "metadata-test.txt",
                "encrypted metadata test",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const storedFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            storedFile,
            "File database record was not created"
        );


        assert.equal(
            storedFile.encrypted,
            true,
            "Uploaded file was not marked encrypted"
        );


        assert.ok(
            storedFile.iv,
            "Encryption IV was not stored"
        );


        assert.ok(
            storedFile.hash,
            "Encrypted file hash was not stored"
        );

    }
);


/* =========================================================
   4. IV MUST NOT EQUAL GLOBAL KEY
   ========================================================= */

test(
    "stored IV is not identical to configured encryption key",
    async () => {

        const response =
            await upload(
                "iv-key-test.txt",
                "IV/key separation test",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const storedFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            storedFile
        );


        const key =
            process.env.ENCRYPTION_KEY ||
            null;


        if (key) {

            assert.notEqual(
                storedFile.iv,
                key,
                "IV is identical to global encryption key"
            );

        }

    }
);


/* =========================================================
   5. CLIENT CANNOT SUPPLY ENCRYPTION METADATA
   ========================================================= */

test(
    "client-supplied encryption metadata cannot become trusted metadata",
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
                        "metadata-attack.txt",

                    encrypted:
                        false,

                    iv:
                        "attacker-controlled-iv",

                    hash:
                        "attacker-controlled-hash",

                    encryptionKey:
                        "attacker-controlled-key"

                });


        assert.notEqual(
            response.status,
            201,
            "Client-controlled encryption metadata created a file"
        );


        const files =
            await File.find({
                owner:
                    user.id
            });


        assert.equal(
            files.length,
            0,
            "Invalid metadata request created a file"
        );

    }
);


/* =========================================================
   6. INVALID ENCRYPTION METADATA IS NOT RETURNED
   ========================================================= */

test(
    "failed encryption-related request does not expose sensitive metadata",
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

                    encrypted:
                        "not-a-boolean",

                    iv:
                        {
                            value:
                                "secret"
                        },

                    hash:
                        {
                            value:
                                "secret"
                        }

                });


        assert.notEqual(
            response.status,
            500
        );


        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();


        assert.equal(
            body.includes(
                "attacker-controlled-key"
            ),
            false
        );

    }
);


/* =========================================================
   7. DATABASE DOES NOT STORE GLOBAL KEY IN IV
   ========================================================= */

test(
    "database IV does not contain the global encryption key",
    async () => {

        const response =
            await upload(
                "global-key-test.txt",
                "global key separation",
                "text/plain"
            );


        assert.equal(
            response.status,
            201
        );


        const storedFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            storedFile
        );


        const key =
            process.env.ENCRYPTION_KEY ||
            "";


        if (key) {

            assert.equal(
                String(storedFile.iv).includes(key),
                false,
                "Global encryption key appears inside IV"
            );

        }

    }
);


/* =========================================================
   8. HASH IS NOT PLAINTEXT FILE CONTENT
   ========================================================= */

test(
    "stored hash does not contain plaintext file content",
    async () => {

        const secretContent =
            "VERY-SECRET-PLAINTEXT-DATA";


        const response =
            await upload(
                "hash-test.txt",
                secretContent,
                "text/plain"
            );


        assert.equal(
            response.status,
            201
        );


        const storedFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            storedFile
        );


        assert.equal(
            String(storedFile.hash).includes(
                secretContent
            ),
            false,
            "Plaintext content was stored inside file hash"
        );

    }
);


/* =========================================================
   9. FAILED UPLOAD DOES NOT LEAVE INVALID ENCRYPTION RECORD
   ========================================================= */

test(
    "failed upload does not leave an incomplete encryption record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await upload(
                "bad.exe",
                "fake executable",
                "application/octet-stream"
            );


        assert.equal(
            response.status,
            400
        );


        const afterCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        assert.equal(
            afterCount,
            beforeCount,
            "Failed encryption/upload request left a database record"
        );

    }
);


/* =========================================================
   10. INTERNAL ENCRYPTION FIELDS NOT EXPOSED
   ========================================================= */

test(
    "file listing does not expose encryption secrets",
    async () => {

        await upload(
            "listing-secret.txt",
            "secure listing content",
            "text/plain"
        );


        const response =
            await request(app)
                .get(
                    "/api/files"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            200
        );


        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();


        assert.equal(
            body.includes(
                "encryptionkey"
            ),
            false
        );


        assert.equal(
            body.includes(
                "encryption_key"
            ),
            false
        );


        /*
         * IV may be considered internal cryptographic metadata
         * and should not normally be returned in a file listing.
         */
        assert.equal(
            body.includes(
                "\"iv\""
            ),
            false,
            "Encryption IV exposed through file listing"
        );

    }
);