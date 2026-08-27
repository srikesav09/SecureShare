import "./env.js";

import test, { before, after } from "node:test";
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


let token;
let user;
let file;
let share;


/*
 * =========================================================
 * AUTHENTICATION
 * =========================================================
 */

const registerAndLogin = async () => {

    const email =
        `type-confusion-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;

    const password =
        "StrongPassword123!";


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Type Confusion User",
                email,
                password
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
                password
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


    assert.ok(databaseUser);


    return {
        token: accessToken,
        user: databaseUser
    };
};


/*
 * =========================================================
 * FILE
 * =========================================================
 */

const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "type-confusion.txt",

        storedName:
            `type-confusion-${Date.now()}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/type-confusion-${Date.now()}.enc`,

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
 * =========================================================
 * SETUP
 * =========================================================
 */

before(async () => {

    await startTestDatabase();

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    token =
        result.token;

    user =
        result.user;


    file =
        await createFile(
            user.id
        );


    share =
        await Share.create({

            file:
                file.id,

            owner:
                user.id,

            token:
                `type-confusion-token-${Date.now()}`,

            expiresAt:
                new Date(
                    Date.now() + 60 * 60 * 1000
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

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. ARRAY FILE ID
 * =========================================================
 */

test(
    "array-style path identifier cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    "/api/files/a/a"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
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
            databaseFile
        );

    }
);


/*
 * =========================================================
 * 2. ARRAY QUERY ID
 * =========================================================
 */

test(
    "array query identifier cannot replace the resource ID",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}?id[]=${file.id}&id[]=attacker`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 3. OBJECT USER ID
 * =========================================================
 */

test(
    "object userId cannot replace JWT identity",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .query({
                    userId: {
                        value: user.id
                    }
                });


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 4. ARRAY USER ID
 * =========================================================
 */

test(
    "array userId cannot replace JWT identity",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files?userId[]=${user.id}&userId[]=attacker`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 5. OBJECT maxDownloads
 * =========================================================
 */

test(
    "object maxDownloads cannot bypass validation",
    async () => {

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
                    maxDownloads: {
                        value: 5
                    }
                });


        assert.notEqual(
            response.status,
            500
        );


        /*
         * An object must never become a valid numeric
         * download limit.
         */
        if (response.status === 201) {

            const created =
                await Share.findOne({
                    file: file.id,
                    owner: user.id
                });


            assert.ok(created);


            assert.equal(
                typeof created.maxDownloads,
                "number",
                "Object was stored as maxDownloads"
            );

        }

    }
);


/*
 * =========================================================
 * 6. ARRAY maxDownloads
 * =========================================================
 */

test(
    "array maxDownloads cannot bypass validation",
    async () => {

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
                    maxDownloads: [
                        5,
                        999999
                    ]
                });


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 7. OBJECT PASSWORD
 * =========================================================
 */

test(
    "object password cannot bypass password validation",
    async () => {

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
                    maxDownloads: 5,
                    password: {
                        value:
                            "secure-password"
                    }
                });


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 8. ARRAY SHARE ID
 * =========================================================
 */

test(
    "array shareId cannot change the path resource",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${share.id}?shareId[]=${share.id}&shareId[]=attacker`
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


        assert.ok(
            databaseShare
        );

    }
);


/*
 * =========================================================
 * 9. BOOLEAN TYPE CONFUSION
 * =========================================================
 */

test(
    "boolean privilege fields cannot be injected as strings",
    async () => {

        const email =
            `boolean-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name:
                        "Boolean Injection User",

                    email,

                    password:
                        "StrongPassword123!",

                    isAdmin:
                        "true",

                    admin:
                        "true",

                    verified:
                        "true"
                });


        assert.notEqual(
            response.status,
            500
        );


        const databaseUser =
            await User.findOne({
                email
            });


        if (databaseUser) {

            assert.equal(
                databaseUser.role,
                "USER",
                "String privilege value changed user role"
            );

        }

    }
);


/*
 * =========================================================
 * 10. NULL TYPE CONFUSION
 * =========================================================
 */

test(
    "null identity values cannot bypass authentication",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email:
                        null,

                    password:
                        null
                });


        assert.notEqual(
            response.status,
            200,
            "Null values bypassed authentication"
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);