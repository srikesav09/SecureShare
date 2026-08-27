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

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD =
    "JsonAbuseSecurity123!";

let user;
let token;


/* =========================================================
   AUTHENTICATION
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `json-abuse-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "JSON Abuse User",

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
        databaseUser,
        "User was not found"
    );

    return {
        user:
            databaseUser,

        token:
            accessToken
    };
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

    await clearTestDatabase();

    const result =
        await registerAndLogin();

    user =
        result.user;

    token =
        result.token;
});


beforeEach(async () => {

    /*
     * Do not clear the database here.
     *
     * The authenticated user and JWT are shared across
     * the entire test file so the login rate limiter is
     * not consumed once per test.
     */

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. EMPTY JSON OBJECT
   ========================================================= */

test(
    "empty JSON object is handled safely",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/register"
                )
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send({});

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   2. NULL BODY
   ========================================================= */

test(
    "null JSON body is handled safely",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/register"
                )
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send(null);

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   3. ARRAY BODY
   ========================================================= */

test(
    "array JSON body cannot replace object validation",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/register"
                )
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send([
                    "admin",
                    "password"
                ]);

        assert.notEqual(
            response.status,
            500
        );

        assert.notEqual(
            response.status,
            201,
            "Array body was accepted as registration data"
        );

    }
);


/* =========================================================
   4. STRING BODY
   ========================================================= */

test(
    "string JSON body cannot bypass validation",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/register"
                )
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send("admin");

        assert.notEqual(
            response.status,
            500
        );

        assert.notEqual(
            response.status,
            201
        );

    }
);


/* =========================================================
   5. OVERSIZED FIELD
   ========================================================= */

test(
    "very large JSON field does not crash the server",
    async () => {

        const hugeValue =
            "A".repeat(
                1024 * 1024
            );

        const response =
            await request(app)
                .post(
                    "/api/auth/register"
                )
                .send({
                    name:
                        hugeValue,

                    email:
                        `huge-${Date.now()}@example.com`,

                    password:
                        PASSWORD
                });

        assert.ok(
            response.status < 500,
            `Server returned ${response.status}`
        );

    }
);


/* =========================================================
   6. MANY JSON FIELDS
   ========================================================= */

test(
    "large number of JSON fields does not crash the server",
    async () => {

        const payload = {};

        for (let i = 0; i < 2000; i++) {

            payload[
                `field${i}`
            ] =
                `value-${i}`;

        }

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send(
                    payload
                );

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   7. DEEP NESTING
   ========================================================= */

test(
    "deeply nested JSON does not crash the server",
    async () => {

        let nested =
            "value";

        for (let i = 0; i < 100; i++) {

            nested = {
                value:
                    nested
            };

        }

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send({

                    email:
                        nested,

                    password:
                        nested

                });

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   8. MIXED TYPES
   ========================================================= */

test(
    "mixed scalar and object types are safely rejected",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send({

                    email: [
                        user.email,
                        {
                            $ne:
                                null
                        }
                    ],

                    password: [
                        PASSWORD,
                        {
                            $ne:
                                null
                        }
                    ]

                });

        assert.notEqual(
            response.status,
            200,
            "Mixed-type credentials bypassed authentication"
        );

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   9. LARGE AUTHENTICATED QUERY
   ========================================================= */

test(
    "large authenticated query does not bypass authorization",
    async () => {

        const params =
            new URLSearchParams();

        for (let i = 0; i < 1000; i++) {

            params.append(
                `parameter${i}`,
                `value-${i}`
            );

        }

        const response =
            await request(app)
                .get(
                    `/api/files?${params.toString()}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );

        assert.notEqual(
            response.status,
            401,
            "Valid JWT was unexpectedly rejected"
        );

        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   10. PROTOTYPE-LIKE KEYS
   ========================================================= */

test(
    "prototype-like JSON keys do not alter authentication",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send({

                    email:
                        user.email,

                    password:
                        "wrong-password",

                    "__proto__":
                        {
                            role:
                                "ADMIN"
                        },

                    constructor:
                        {
                            role:
                                "ADMIN"
                        },

                    prototype:
                        {
                            role:
                                "ADMIN"
                        }

                });

        assert.notEqual(
            response.status,
            200,
            "Prototype-like fields bypassed authentication"
        );

        assert.notEqual(
            response.status,
            500
        );

    }
);