import "./env.js";

import test, {
    before,
    beforeEach,
    after,
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase,
} from "./setup.js";


before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();
});

after(async () => {
    await stopTestDatabase();
});


// =========================================================
// UNKNOWN API ROUTE
// =========================================================

test(
    "unknown API route is rejected safely",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/this-endpoint-does-not-exist"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// INVALID JSON
// =========================================================

test(
    "malformed JSON request is rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send(
                    '{"name":"test","email":'
                );

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// =========================================================
// EMPTY REQUEST BODY
// =========================================================

test(
    "empty registration body is rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({});

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// =========================================================
// NULL VALUES
// =========================================================

test(
    "null authentication fields are rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: null,
                    email: null,
                    password: null,
                });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// =========================================================
// ARRAY INSTEAD OF STRING
// =========================================================

test(
    "array values in authentication fields are rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: ["test"],
                    email: ["test@example.com"],
                    password: ["password123"],
                });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// =========================================================
// OBJECT INSTEAD OF STRING
// =========================================================

test(
    "object values in authentication fields are rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: {
                        value: "test",
                    },
                    email: {
                        value: "test@example.com",
                    },
                    password: {
                        value: "password123",
                    },
                });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// =========================================================
// UNEXPECTED FIELDS
// =========================================================

test(
    "unexpected registration fields do not cause server error",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email:
                        `abuse-${Date.now()}@example.com`,
                    password: "password123",

                    isAdmin: true,
                    role: "admin",
                    permissions: ["admin"],
                });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// EXTREMELY LONG INPUT
// =========================================================

test(
    "extremely long name is handled safely",
    async () => {

        const longName =
            "A".repeat(10000);

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: longName,
                    email:
                        `long-${Date.now()}@example.com`,
                    password: "password123",
                });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// EXTREMELY LONG EMAIL
// =========================================================

test(
    "extremely long email is handled safely",
    async () => {

        const longEmail =
            `${"a".repeat(10000)}@example.com`;

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email: longEmail,
                    password: "password123",
                });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// PROTOTYPE POLLUTION STYLE INPUT
// =========================================================

test(
    "prototype pollution style input is handled safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email:
                        `proto-${Date.now()}@example.com`,
                    password: "password123",

                    "__proto__": {
                        isAdmin: true,
                    },

                    "constructor": {
                        prototype: {
                            isAdmin: true,
                        },
                    },
                });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// SQL / NOSQL INJECTION STYLE INPUT
// =========================================================

test(
    "NoSQL injection style registration input is handled safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: {
                        $ne: null,
                    },

                    email: {
                        $ne: null,
                    },

                    password: {
                        $ne: null,
                    },
                });

        assert.notEqual(
            response.status,
            500
        );

        assert.ok(
            response.status >= 400
        );
    }
);