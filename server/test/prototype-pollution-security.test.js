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


let token;
let user;
let file;


/*
 * =========================================================
 * HELPERS
 * =========================================================
 */

const registerAndLogin = async () => {

    const email =
        `prototype-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const password =
        "PrototypeSecurity123!";


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Prototype Security User",
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
        `JWT token not returned: ${JSON.stringify(login.body)}`
    );


    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(
        databaseUser,
        "User was not found in database"
    );


    return {
        token: accessToken,
        user: databaseUser
    };
};


const createFile = async (ownerId) => {

    return File.create({

        originalName:
            "prototype-test.txt",

        storedName:
            `prototype-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/prototype-${Date.now()}.enc`,

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

});


beforeEach(async () => {

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    token =
        result.token;

    user =
        result.user;


    file =
        await createFile(user.id);

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. __proto__ IN REGISTRATION
 * =========================================================
 */

test(
    "__proto__ cannot inject privileged registration fields",
    async () => {

        const email =
            `proto-role-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Prototype User",
                    email,
                    password: "Password123!",
                    "__proto__": {
                        role: "ADMIN"
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
            databaseUser,
            "User was not created"
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Prototype pollution granted ADMIN privileges"
        );

    }
);


/*
 * =========================================================
 * 2. CONSTRUCTOR POLLUTION
 * =========================================================
 */

test(
    "constructor payload cannot inject privileged fields",
    async () => {

        const email =
            `constructor-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Constructor User",
                    email,
                    password: "Password123!",
                    constructor: {
                        prototype: {
                            role: "ADMIN"
                        }
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
            databaseUser,
            "User was not created"
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Constructor pollution granted ADMIN privileges"
        );

    }
);


/*
 * =========================================================
 * 3. PROTOTYPE FIELD
 * =========================================================
 */

test(
    "prototype field cannot alter request object behavior",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Prototype Field User",
                    email:
                        `prototype-field-${Date.now()}@example.com`,
                    password: "Password123!",
                    prototype: {
                        role: "ADMIN"
                    }
                });


        assert.equal(
            response.status,
            201,
            `Unexpected response: ${JSON.stringify(response.body)}`
        );


        assert.equal(
            response.body?.data?.role ||
            response.body?.role,
            "USER",
            "Prototype field altered user privilege"
        );

    }
);




/*
 * =========================================================
 * 4. __proto__ CANNOT CHANGE AUTHENTICATED IDENTITY
 * =========================================================
 */

test(
    "__proto__ cannot change authenticated identity",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    "__proto__": {
                        userId: "attacker",
                        owner: "attacker",
                        role: "ADMIN"
                    }
                });


        /*
         * A valid JWT must remain authoritative.
         *
         * The prototype payload must not replace the
         * authenticated user.
         */

        assert.notEqual(
            response.status,
            401,
            "Prototype payload replaced valid JWT identity"
        );


        const databaseUser =
            await User.findById(user.id);


        assert.ok(
            databaseUser,
            "Authenticated user disappeared"
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Prototype pollution changed user privilege"
        );


        assert.equal(
            Object.prototype.role,
            undefined,
            "Object.prototype.role was polluted"
        );

    }
);




/*
 * =========================================================
 * 5. CONSTRUCTOR CANNOT CHANGE AUTHENTICATED IDENTITY
 * =========================================================
 */

test(
    "constructor pollution cannot change authenticated identity",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .send({
                    constructor: {
                        prototype: {
                            userId: "attacker",
                            owner: "attacker",
                            role: "ADMIN"
                        }
                    }
                });


        /*
         * The request must still use the identity
         * supplied by the JWT.
         */

        assert.notEqual(
            response.status,
            401,
            "Constructor payload replaced valid JWT identity"
        );


        const databaseUser =
            await User.findById(user.id);


        assert.ok(
            databaseUser,
            "Authenticated user disappeared"
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Constructor pollution changed user privilege"
        );


        assert.equal(
            Object.prototype.role,
            undefined,
            "Constructor pollution modified Object.prototype"
        );

    }
);


/*
 * =========================================================
 * 6. JSON POLLUTION CANNOT GRANT ADMIN
 * =========================================================
 */

test(
    "nested prototype payload cannot grant ADMIN privileges",
    async () => {

        const email =
            `nested-proto-${Date.now()}@example.com`;


        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Nested Prototype User",
                    email,
                    password: "Password123!",
                    settings: {
                        "__proto__": {
                            role: "ADMIN"
                        }
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
            "Nested prototype payload granted ADMIN"
        );

    }
);


/*
 * =========================================================
 * 7. GLOBAL OBJECTS MUST REMAIN CLEAN
 * =========================================================
 */

test(
    "prototype pollution payload does not modify Object.prototype",
    async () => {

        const marker =
            `polluted-${Date.now()}`;


        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Pollution Test",
                email:
                    `global-proto-${Date.now()}@example.com`,
                password: "Password123!",
                "__proto__": {
                    polluted: marker
                }
            });


        assert.equal(
            Object.prototype.polluted,
            undefined,
            "Object.prototype was polluted"
        );


        assert.equal(
            Object.prototype.role,
            undefined,
            "Object.prototype.role was modified"
        );

    }
);


/*
 * =========================================================
 * 8. ARRAY PROTOTYPE POLLUTION
 * =========================================================
 */

test(
    "array prototype pollution payload is rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Array Pollution User",
                    email:
                        `array-proto-${Date.now()}@example.com`,
                    password: "Password123!",
                    "__proto__": {
                        "0": "attacker"
                    }
                });


        assert.notEqual(
            response.status,
            500,
            "Prototype payload caused server crash"
        );


        assert.equal(
            Array.prototype.polluted,
            undefined,
            "Array.prototype was polluted"
        );

    }
);


/*
 * =========================================================
 * 9. AUTHORIZATION REMAINS JWT BASED
 * =========================================================
 */

test(
    "prototype payload cannot replace authenticated identity",
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
                .send({
                    "__proto__": {
                        userId: "attacker"
                    }
                });


        assert.notEqual(
            response.status,
            401,
            "Prototype payload replaced valid JWT identity"
        );


        const databaseFile =
            await File.findById(file.id);


        assert.ok(
            databaseFile
        );


        assert.equal(
            String(databaseFile.owner),
            String(user.id),
            "Prototype payload changed resource ownership"
        );

    }
);


/*
 * =========================================================
 * 10. POLLUTION DOES NOT PERSIST BETWEEN REQUESTS
 * =========================================================
 */

test(
    "prototype pollution cannot persist into subsequent requests",
    async () => {

        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Pollution Attempt",
                email:
                    `persist-${Date.now()}@example.com`,
                password: "Password123!",
                "__proto__": {
                    role: "ADMIN"
                }
            });


        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.notEqual(
            response.status,
            500,
            "Prototype pollution corrupted subsequent request"
        );


        assert.equal(
            Object.prototype.role,
            undefined,
            "Prototype pollution persisted globally"
        );

    }
);