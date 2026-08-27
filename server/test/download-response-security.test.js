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
    "DownloadResponseSecurity123!";

let user;
let token;
let file;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `download-response-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Download Response User",

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


const createFile = async (
    ownerId,
    overrides = {}
) => {

    return File.create({

        originalName:
            "download-response.txt",

        storedName:
            `download-response-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `private/download-response-${Date.now()}.enc`,

        owner:
            ownerId,

        encrypted:
            true,

        iv:
            "internal-test-iv",

        hash:
            "internal-test-hash",

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

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. INVALID ID
   ========================================================= */

test(
    "invalid file ID does not produce a server crash",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-valid-id/download"
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
            [400, 404].includes(
                response.status
            )
        );

    }
);


/* =========================================================
   2. NONEXISTENT FILE
   ========================================================= */

test(
    "nonexistent file cannot be downloaded",
    async () => {

        const mongoose =
            await import("mongoose");


        const fakeId =
            new mongoose.Types.ObjectId();


        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            404
        );

    }
);


/* =========================================================
   3. DELETED FILE
   ========================================================= */

test(
    "deleted file cannot be downloaded",
    async () => {

        const fileId =
            file.id;


        await File.findByIdAndDelete(
            fileId
        );


        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            404
        );

    }
);


/* =========================================================
   4. NO INTERNAL S3 KEY IN ERROR
   ========================================================= */

test(
    "download error does not expose S3 key",
    async () => {

        const secretKey =
            file.s3Key;


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                secretKey
            ),
            false
        );

    }
);


/* =========================================================
   5. NO INTERNAL IV IN ERROR
   ========================================================= */

test(
    "download error does not expose encryption IV",
    async () => {

        const secretIv =
            file.iv;


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                secretIv
            ),
            false
        );

    }
);


/* =========================================================
   6. NO INTERNAL HASH IN ERROR
   ========================================================= */

test(
    "download error does not expose internal file hash",
    async () => {

        const secretHash =
            file.hash;


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const body =
            JSON.stringify(
                response.body
            );


        assert.equal(
            body.includes(
                secretHash
            ),
            false
        );

    }
);


/* =========================================================
   7. AUTHENTICATION CANNOT BE REPLACED BY QUERY TOKEN
   ========================================================= */

test(
    "query token cannot replace Authorization JWT",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download?token=fake-token`
                );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   8. BASIC AUTH CANNOT DOWNLOAD
   ========================================================= */

test(
    "Basic authorization cannot authenticate file download",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    "Basic attacker-token"
                );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   9. DOWNLOAD RESPONSE DOES NOT LEAK INTERNAL METADATA
   ========================================================= */

test(
    "download endpoint does not return database metadata",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const contentDisposition =
            response.headers[
                "content-disposition"
            ];


        if (contentDisposition) {

            assert.equal(
                contentDisposition.includes(
                    file.s3Key
                ),
                false
            );


            assert.equal(
                contentDisposition.includes(
                    file.iv
                ),
                false
            );


            assert.equal(
                contentDisposition.includes(
                    file.hash
                ),
                false
            );

        }

    }
);


/* =========================================================
   10. RESPONSE HEADERS DO NOT EXPOSE INTERNAL PATH
   ========================================================= */

test(
    "download response does not expose server filesystem path",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const headerText =
            Object.entries(
                response.headers
            )
                .map(
                    ([key, value]) =>
                        `${key}:${value}`
                )
                .join("\n")
                .toLowerCase();


        assert.equal(
            headerText.includes(
                process.cwd().toLowerCase()
            ),
            false
        );


        assert.equal(
            headerText.includes(
                "node_modules"
            ),
            false
        );


        assert.equal(
            headerText.includes(
                "src/controllers"
            ),
            false
        );

    }
);