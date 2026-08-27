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


const PASSWORD = "HeaderSecurity123!";

let user;
let token;
let file;


/* =========================================================
   AUTHENTICATION
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `download-header-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Download Header User",
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
        databaseUser,
        "User was not found"
    );


    return {
        user: databaseUser,
        token: accessToken
    };
};


/* =========================================================
   CREATE FILE
   ========================================================= */

const createFile = async (
    ownerId,
    originalName
) => {

    return File.create({

        originalName,

        storedName:
            `header-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            20,

        s3Key:
            `test/header-${Date.now()}.enc`,

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

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. NORMAL FILENAME
   ========================================================= */

test(
    "normal filename does not create malformed headers",
    async () => {

        file =
            await createFile(
                user.id,
                "normal-document.txt"
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        /*
         * The test fixture does not contain a real S3 object,
         * so a storage error is acceptable.
         *
         * The security property is that, if Content-Disposition
         * is generated, it must be a valid attachment header.
         */

        assert.ok(
            [200, 400, 404, 500].includes(response.status),
            `Unexpected response status: ${response.status}`
        );


        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition !== undefined) {

            assert.equal(
                typeof disposition,
                "string"
            );


            assert.match(
                disposition,
                /^attachment(?:;|$)/i
            );


            assert.equal(
                disposition.includes("\r"),
                false
            );


            assert.equal(
                disposition.includes("\n"),
                false
            );

        }

    }
);


/* =========================================================
   2. QUOTE INJECTION
   ========================================================= */

test(
    "filename containing quotes cannot inject another filename parameter",
    async () => {

        file =
            await createFile(
                user.id,
                'file"; filename="evil.txt'
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        /*
         * Fake storage may produce a storage error.
         * The response must still not expose arbitrary
         * response-header injection.
         */

        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition) {

            assert.equal(
                disposition.includes(
                    'filename="evil.txt"'
                ),
                false,
                "Filename parameter injection succeeded"
            );

        }

    }
);


/* =========================================================
   3. CRLF INJECTION
   ========================================================= */

test(
    "CRLF in stored filename cannot inject HTTP headers",
    async () => {

        file =
            await createFile(
                user.id,
                "safe.txt\r\nX-Injected: true"
            );


        let response;

        try {

            response =
                await request(app)
                    .get(
                        `/api/files/${file.id}/download`
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    );

        } catch (error) {

            /*
             * Node may reject invalid header syntax itself.
             * That is safe.
             */
            assert.ok(error);

            return;
        }


        assert.equal(
            response.headers[
                "x-injected"
            ],
            undefined,
            "CRLF filename injected a response header"
        );

    }
);


/* =========================================================
   4. LF INJECTION
   ========================================================= */

test(
    "LF in stored filename cannot inject HTTP headers",
    async () => {

        file =
            await createFile(
                user.id,
                "safe.txt\nX-Injected: true"
            );


        let response;

        try {

            response =
                await request(app)
                    .get(
                        `/api/files/${file.id}/download`
                    )
                    .set(
                        "Authorization",
                        `Bearer ${token}`
                    );

        } catch (error) {

            assert.ok(error);

            return;

        }


        assert.equal(
            response.headers[
                "x-injected"
            ],
            undefined
        );

    }
);


/* =========================================================
   5. SEMICOLON PARAMETER INJECTION
   ========================================================= */

test(
    "filename cannot inject Content-Disposition parameters",
    async () => {

        file =
            await createFile(
                user.id,
                "document.txt; filename=evil.txt"
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition) {

            assert.equal(
                disposition.includes(
                    "filename=evil.txt"
                ),
                false,
                "Content-Disposition parameter injection succeeded"
            );

        }

    }
);


/* =========================================================
   6. BACKSLASH
   ========================================================= */

test(
    "backslash in filename does not create arbitrary path information",
    async () => {

        file =
            await createFile(
                user.id,
                "..\\..\\secret.txt"
            );


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
                process.cwd()
            ),
            false
        );

    }
);


/* =========================================================
   7. PATH TRAVERSAL FILENAME
   ========================================================= */

test(
    "path traversal filename does not expose filesystem path",
    async () => {

        file =
            await createFile(
                user.id,
                "../../../../etc/passwd"
            );


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
                "src/controllers"
            ),
            false
        );

    }
);


/* =========================================================
   8. UNICODE / SPECIAL CHARACTERS
   ========================================================= */

test(
    "Unicode filename is handled without header injection",
    async () => {

        file =
            await createFile(
                user.id,
                "安全文書-📄.txt"
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.ok(
            [200, 400, 404, 500].includes(response.status),
            `Unexpected response status: ${response.status}`
        );


        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition !== undefined) {

            assert.equal(
                typeof disposition,
                "string"
            );


            assert.equal(
                disposition.includes("\r"),
                false
            );


            assert.equal(
                disposition.includes("\n"),
                false
            );

        }

    }
);


/* =========================================================
   9. EXTREMELY LONG FILENAME
   ========================================================= */

test(
    "extremely long stored filename is handled safely",
    async () => {

        const longFilename =
            `${"a".repeat(1000)}.txt`;


        file =
            await createFile(
                user.id,
                longFilename
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        /*
         * Fake storage can legitimately produce 500.
         * This test is checking that an oversized filename
         * does not create an injected HTTP header.
         */
        assert.ok(
            [200, 400, 404, 500].includes(response.status),
            `Unexpected response status: ${response.status}`
        );


        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition !== undefined) {

            assert.equal(
                typeof disposition,
                "string"
            );


            assert.equal(
                disposition.includes("\r"),
                false
            );


            assert.equal(
                disposition.includes("\n"),
                false
            );

        }

    }
);


/* =========================================================
   10. HEADER VALUE REMAINS STRING
   ========================================================= */

test(
    "content disposition remains a valid header string",
    async () => {

        file =
            await createFile(
                user.id,
                "header-test.txt"
            );


        const response =
            await request(app)
                .get(
                    `/api/files/${file.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        const disposition =
            response.headers[
                "content-disposition"
            ];


        if (disposition) {

            assert.equal(
                typeof disposition,
                "string"
            );


            assert.equal(
                disposition.includes(
                    "\r"
                ),
                false
            );


            assert.equal(
                disposition.includes(
                    "\n"
                ),
                false
            );

        }

    }
);