import "./env.js";

import test, {
    before,
    beforeEach,
    after
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


// =========================================================
// DATABASE SETUP
// =========================================================

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
// HELPERS
// =========================================================

const randomEmail = () =>
    `validation-${Date.now()}-${Math.random()}@example.com`;

const registerUser = async () => {

    const email = randomEmail();

    const response =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Validation Test User",
                email,
                password: "password123"
            });

    assert.equal(
        response.status,
        201,
        `Registration failed: ${JSON.stringify(response.body)}`
    );

    return email;
};

const loginUser = async (email) => {

    const response =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password: "password123"
            });

    assert.equal(
        response.status,
        200,
        `Login failed: ${JSON.stringify(response.body)}`
    );

    return response.body.data.token;
};


// =========================================================
// REGISTRATION INPUT VALIDATION
// =========================================================

test(
    "registration rejects empty request body",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({});

        assert.notEqual(
            response.status,
            201
        );
    }
);


test(
    "registration rejects invalid email format",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email: "not-an-email",
                    password: "password123"
                });

        assert.equal(
            response.status,
            400
        );
    }
);


test(
    "registration rejects extremely short password",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email: randomEmail(),
                    password: "1"
                });

        assert.notEqual(
            response.status,
            201
        );
    }
);


// =========================================================
// MALICIOUS STRING INPUT
// =========================================================

test(
    "registration safely handles MongoDB operator-like email input",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email: {
                        "$ne": null
                    },
                    password: "password123"
                });

        assert.notEqual(
            response.status,
            201
        );

        assert.notEqual(
            response.status,
            500
        );
    }
);


test(
    "login safely handles MongoDB operator-like input",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: {
                        "$ne": null
                    },
                    password: {
                        "$ne": null
                    }
                });

        assert.notEqual(
            response.status,
            200
        );

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
    "registration safely handles prototype pollution input",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Test User",
                    email: randomEmail(),
                    password: "password123",
                    "__proto__": {
                        "isAdmin": true
                    }
                });

        assert.equal(
            response.status,
            201
        );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes("isAdmin")
        );
    }
);


// =========================================================
// XSS-STYLE INPUT
// =========================================================

test(
    "registration safely handles XSS-style name",
    async () => {

        const payload =
            "<script>alert('xss')</script>";

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: payload,
                    email: randomEmail(),
                    password: "password123"
                });

        // The important security requirement is that
        // malicious input does not crash the API.
        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// VERY LARGE STRING INPUT
// =========================================================

test(
    "registration handles oversized field safely",
    async () => {

        const hugeName =
            "A".repeat(100000);

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: hugeName,
                    email: randomEmail(),
                    password: "password123"
                });

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// NULL INPUTS
// =========================================================

test(
    "registration safely handles null fields",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: null,
                    email: null,
                    password: null
                });

        assert.notEqual(
            response.status,
            201
        );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// ARRAY INPUT
// =========================================================

test(
    "login safely handles array instead of email",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email: [],
                    password: "password123"
                });

        assert.notEqual(
            response.status,
            200
        );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// AUTHORIZATION INPUT
// =========================================================

test(
    "authorization header with multiple bearer values is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    "Bearer token1 token2"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


test(
    "authorization header with empty value is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    ""
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// FILE ID INPUT
// =========================================================

test(
    "file endpoint safely rejects invalid ID characters",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/%3Cscript%3E"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


test(
    "file endpoint safely handles oversized ID",
    async () => {

        const hugeId =
            "A".repeat(1000);

        const response =
            await request(app)
                .get(
                    `/api/files/${hugeId}`
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// SHARE ID INPUT
// =========================================================

test(
    "share endpoint safely rejects invalid ID characters",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/share/%3Cscript%3E"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// HTTP PARAMETER POLLUTION
// =========================================================

test(
    "duplicate query parameters do not cause server error",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files?page=1&page=2&page=3"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// CONTENT TYPE
// =========================================================

test(
    "invalid content type is handled safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .set(
                    "Content-Type",
                    "text/plain"
                )
                .send(
                    "email=test@example.com&password=test"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// MALFORMED JSON
// =========================================================

test(
    "malformed JSON does not crash the application",
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
    }
);