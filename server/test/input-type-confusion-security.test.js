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


let user;
let token;
let file;


/*
 * =========================================================
 * HELPERS
 * =========================================================
 */

const registerAndLogin = async () => {

    const email =
        `type-confusion-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;

    const password =
        "TypeConfusion123!";


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Type Confusion User",
                email,
                password
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
        "JWT token was not returned"
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


const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "type-confusion.txt",

        storedName:
            `type-confusion-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

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

    await User.deleteMany({});
    await File.deleteMany({});

    const result =
        await registerAndLogin();

    user =
        result.user;

    token =
        result.token;
});


beforeEach(async () => {

    await File.deleteMany({});

    file =
        await createFile(user.id);

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. ARRAY EMAIL
 * =========================================================
 */

test(
    "login rejects array-valued email",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: [
                        user.email
                    ],
                    password: "wrong-password"
                });


        assert.notEqual(
            response.status,
            200,
            "Array email was accepted as a valid login identity"
        );

    }
);


/*
 * =========================================================
 * 2. OBJECT EMAIL
 * =========================================================
 */

test(
    "login rejects object-valued email",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: {
                        value: user.email
                    },
                    password: "wrong-password"
                });


        assert.notEqual(
            response.status,
            200,
            "Object email was accepted"
        );

    }
);


/*
 * =========================================================
 * 3. ARRAY PASSWORD
 * =========================================================
 */

test(
    "login rejects array-valued password",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: user.email,
                    password: [
                        "TypeConfusion123!"
                    ]
                });


        assert.notEqual(
            response.status,
            200,
            "Array password bypassed authentication"
        );

    }
);


/*
 * =========================================================
 * 4. OBJECT PASSWORD
 * =========================================================
 */

test(
    "login rejects object-valued password",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: user.email,
                    password: {
                        value: "TypeConfusion123!"
                    }
                });


        assert.notEqual(
            response.status,
            200,
            "Object password bypassed authentication"
        );

    }
);


/*
 * =========================================================
 * 5. ARRAY USER ID
 * =========================================================
 */

test(
    "array-valued resource ID cannot bypass authorization",
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
                .query({
                    id: [
                        file.id,
                        "attacker"
                    ]
                });


        assert.notEqual(
            response.status,
            500,
            "Array resource ID caused server error"
        );


        const databaseFile =
            await File.findById(file.id);


        assert.ok(
            databaseFile,
            "File unexpectedly disappeared"
        );


        assert.equal(
            String(databaseFile.owner),
            String(user.id)
        );

    }
);


/*
 * =========================================================
 * 6. OBJECT USER ID
 * =========================================================
 */

test(
    "object-valued user ID cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    userId: {
                        value: "attacker"
                    }
                });


        /*
         * The request is made with the legitimate owner JWT.
         * The object must not alter the authenticated identity.
         */

        assert.notEqual(
            response.status,
            500,
            "Object userId caused a server error"
        );

    }
);


/*
 * =========================================================
 * 7. ARRAY ROLE
 * =========================================================
 */

test(
    "array-valued role cannot grant ADMIN privileges",
    async () => {

        const email =
            `array-role-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Array Role User",
                    email,
                    password: "Password123!",
                    role: [
                        "ADMIN",
                        "USER"
                    ]
                });


        assert.equal(
            response.status,
            201,
            `Unexpected response: ${JSON.stringify(response.body)}`
        );


        const databaseUser =
            await User.findOne({
                email
            });


        assert.ok(
            databaseUser
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Array role granted ADMIN privileges"
        );

    }
);


/*
 * =========================================================
 * 8. OBJECT ROLE
 * =========================================================
 */

test(
    "object-valued role cannot grant ADMIN privileges",
    async () => {

        const email =
            `object-role-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Object Role User",
                    email,
                    password: "Password123!",
                    role: {
                        value: "ADMIN"
                    }
                });


        assert.equal(
            response.status,
            201,
            `Unexpected response: ${JSON.stringify(response.body)}`
        );


        const databaseUser =
            await User.findOne({
                email
            });


        assert.ok(
            databaseUser
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Object role granted ADMIN privileges"
        );

    }
);


/*
 * =========================================================
 * 9. ARRAY MAX DOWNLOADS
 * =========================================================
 */

test(
    "array-valued maxDownloads cannot bypass validation",
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
            500,
            "Array maxDownloads caused server error"
        );


        assert.notEqual(
            response.status,
            201,
            "Array maxDownloads bypassed validation"
        );

    }
);


/*
 * =========================================================
 * 10. OBJECT MAX DOWNLOADS
 * =========================================================
 */

test(
    "object-valued maxDownloads cannot bypass validation",
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
            500,
            "Object maxDownloads caused server error"
        );


        assert.notEqual(
            response.status,
            201,
            "Object maxDownloads bypassed validation"
        );

    }
);