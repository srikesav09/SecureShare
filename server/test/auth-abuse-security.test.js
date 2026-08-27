import "./env.js";
import assert from "node:assert/strict";
import test, { before, after } from "node:test";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const password = "StrongPassword123!";

let email;

before(async () => {
    await startTestDatabase();

    email = `auth-abuse-${Date.now()}@example.com`;

    const response = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Auth Abuse User",
            email,
            password
        });

    assert.ok(
        [200, 201].includes(response.statusCode),
        `Registration failed: ${JSON.stringify(response.body)}`
    );
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});


test("wrong password is rejected", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password: "WrongPassword123!"
        });

    assert.ok(
        [400, 401, 403, 429].includes(response.statusCode),
        `Unexpected status: ${response.statusCode}`
    );
});


test("nonexistent account is rejected", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: `does-not-exist-${Date.now()}@example.com`,
            password
        });

    assert.ok(
        [400, 401, 403, 404, 429].includes(response.statusCode),
        `Unexpected status: ${response.statusCode}`
    );
});


test("empty email cannot authenticate", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "",
            password
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Empty email must not authenticate"
    );
});


test("empty password cannot authenticate", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password: ""
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Empty password must not authenticate"
    );
});


test("missing credentials are rejected", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "Missing credentials must not authenticate"
    );
});


test("malformed email cannot authenticate", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "not-an-email",
            password
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Malformed email must not authenticate"
    );
});


test("very long password cannot bypass authentication", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password: "A".repeat(10000)
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Long password must not authenticate"
    );
});


test("password is not returned in login response", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });

    if (response.statusCode === 200) {
        const body = JSON.stringify(response.body);

        assert.doesNotMatch(
            body,
            /StrongPassword123!/i,
            "Plaintext password must never appear in response"
        );
    }
});


test("login response does not expose password hash", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });

    if (response.statusCode === 200) {
        const body = JSON.stringify(response.body);

        assert.doesNotMatch(
            body,
            /\$2[aby]\$\d{2}\$/i,
            "bcrypt password hash must not be exposed"
        );
    }
});


test("repeated failed login attempts are eventually rate limited", async () => {
    const attackerEmail =
        `bruteforce-${Date.now()}@example.com`;

    let rateLimited = false;

    for (let i = 0; i < 20; i++) {
        const response = await request(app)
            .post("/api/auth/login")
            .send({
                email: attackerEmail,
                password: "WrongPassword123!"
            });

        if (response.statusCode === 429) {
            rateLimited = true;
            break;
        }
    }

    /*
     * If the application has an authentication rate limiter,
     * repeated attempts should eventually receive 429.
     */
    assert.equal(
        rateLimited,
        true,
        "Repeated authentication attempts should eventually be rate limited"
    );
});