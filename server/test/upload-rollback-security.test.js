import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert/strict";
import request from "supertest";
import fs from "fs";
import path from "path";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD = "RollbackSecurity123!";

const UPLOAD_DIR =
    path.resolve("uploads");

let user;
let token;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `rollback-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Rollback Security User",

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
        "Access token was not returned"
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
        .post("/api/files/upload")
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


const getUploadFiles = () => {

    if (!fs.existsSync(UPLOAD_DIR)) {
        return [];
    }

    return fs
        .readdirSync(UPLOAD_DIR)
        .sort();
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


    if (!fs.existsSync(UPLOAD_DIR)) {

        fs.mkdirSync(
            UPLOAD_DIR,
            {
                recursive: true
            }
        );

    }

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. INVALID EXTENSION MUST NOT CREATE DB RECORD
   ========================================================= */

test(
    "rejected extension does not create a database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await upload(
                "malware.exe",
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
            "Rejected upload created a database record"
        );

    }
);


/* =========================================================
   2. INVALID MIME MUST NOT CREATE DB RECORD
   ========================================================= */

test(
    "rejected MIME type does not create a database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await upload(
                "document.pdf",
                "%PDF-1.7 test",
                "application/javascript"
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
            beforeCount
        );

    }
);


/* =========================================================
   3. INVALID SIGNATURE MUST NOT CREATE RECORD
   ========================================================= */

test(
    "invalid file signature does not create a database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await upload(
                "fake.pdf",
                "This is not actually a PDF",
                "application/pdf"
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
            beforeCount
        );

    }
);


/* =========================================================
   4. MISSING FILE MUST NOT CREATE RECORD
   ========================================================= */

test(
    "request without a file does not create a database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await request(app)
                .post(
                    "/api/files/upload"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({});


        assert.notEqual(
            response.status,
            201
        );


        const afterCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        assert.equal(
            afterCount,
            beforeCount
        );

    }
);


/* =========================================================
   5. OVERSIZED FILE MUST NOT CREATE RECORD
   ========================================================= */

test(
    "oversized upload does not leave a database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const oversized =
            Buffer.alloc(
                10 * 1024 * 1024 + 1,
                "a"
            );


        const response =
            await upload(
                "oversized.txt",
                oversized,
                "text/plain"
            );


        assert.ok(
            [400, 413, 422].includes(
                response.status
            ),
            `Unexpected status: ${response.status}`
        );


        const afterCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        assert.equal(
            afterCount,
            beforeCount,
            "Oversized upload created a database record"
        );

    }
);


/* =========================================================
   6. INVALID UPLOAD MUST NOT LEAVE TEMP FILE
   ========================================================= */

test(
    "rejected upload does not leave uploaded temporary file",
    async () => {

        const marker =
            `rollback-invalid-${Date.now()}`;


        const beforeFiles =
            getUploadFiles();


        const response =
            await upload(
                `${marker}.exe`,
                "invalid executable",
                "application/octet-stream"
            );


        assert.equal(
            response.status,
            400
        );


        const afterFiles =
            getUploadFiles();


        /*
         * No file whose generated name contains the
         * marker should remain.
         */
        const leaked =
            afterFiles.filter(
                filename =>
                    filename.includes(marker)
            );


        assert.equal(
            leaked.length,
            0,
            "Rejected upload left a temporary file"
        );


        /*
         * Existing unrelated files are allowed.
         */
        assert.ok(
            afterFiles.length >= 0
        );

    }
);


/* =========================================================
   7. SUCCESSFUL UPLOAD HAS ONE RECORD
   ========================================================= */

test(
    "successful upload creates exactly one database record",
    async () => {

        const beforeCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        const response =
            await upload(
                "rollback-success.txt",
                "successful rollback test",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const afterCount =
            await File.countDocuments({
                owner:
                    user.id
            });


        assert.equal(
            afterCount,
            beforeCount + 1
        );

    }
);


/* =========================================================
   8. REJECTED UPLOAD DOES NOT ALTER EXISTING RECORDS
   ========================================================= */

test(
    "failed upload does not modify existing file records",
    async () => {

        const validResponse =
            await upload(
                "existing.txt",
                "existing valid file",
                "text/plain"
            );


        assert.equal(
            validResponse.status,
            201,
            JSON.stringify(validResponse.body)
        );


        const existingFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            existingFile
        );


        const before =
            existingFile.toObject();


        const invalidResponse =
            await upload(
                "bad.exe",
                "bad file",
                "application/octet-stream"
            );


        assert.equal(
            invalidResponse.status,
            400
        );


        const after =
            await File.findById(
                existingFile.id
            );


        assert.ok(
            after
        );


        assert.equal(
            String(after.owner),
            String(before.owner)
        );


        assert.equal(
            after.originalName,
            before.originalName
        );


        assert.equal(
            after.s3Key,
            before.s3Key
        );

    }
);


/* =========================================================
   9. TWO FAILED UPLOADS LEAVE NO RECORDS
   ========================================================= */

test(
    "multiple failed uploads leave database clean",
    async () => {

        const failures = [
            [
                "one.exe",
                "bad executable",
                "application/octet-stream"
            ],
            [
                "two.js",
                "bad javascript",
                "application/javascript"
            ],
            [
                "three.html",
                "<script>alert(1)</script>",
                "text/html"
            ]
        ];


        for (
            const [
                filename,
                content,
                contentType
            ] of failures
        ) {

            const response =
                await upload(
                    filename,
                    content,
                    contentType
                );


            assert.equal(
                response.status,
                400,
                `Unexpected status for ${filename}: ${response.status}`
            );

        }


        const count =
            await File.countDocuments({
                owner:
                    user.id
            });


        assert.equal(
            count,
            0,
            "Failed uploads created database records"
        );

    }
);


/* =========================================================
   10. DB RECORD OWNER MUST MATCH AUTHENTICATED USER
   ========================================================= */

test(
    "successful upload database record belongs to authenticated user",
    async () => {

        const response =
            await upload(
                "owner-check.txt",
                "ownership rollback test",
                "text/plain"
            );


        assert.equal(
            response.status,
            201,
            JSON.stringify(response.body)
        );


        const createdFile =
            await File.findOne({
                owner:
                    user.id
            });


        assert.ok(
            createdFile,
            "Upload did not create a file record"
        );


        assert.equal(
            String(createdFile.owner),
            String(user.id),
            "File record owner does not match authenticated user"
        );

    }
);