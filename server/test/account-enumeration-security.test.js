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
let existingEmail;

before(async () => {
    await startTestDatabase();

    existingEmail =
        `enumeration-${Date.now()}@example.com`;

    const response = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Enumeration Test User",
            email: existingEmail,
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


test("wrong password does not reveal whether account exists", async () => {
    const existing = await request(app)
        .post("/api/auth/login")
        .send({
            email: existingEmail,
            password: "WrongPassword123!"
        });

    const nonexistent = await request(app)
        .post("/api/auth/login")
        .send({
            email: `nonexistent-${Date.now()}@example.com`,
            password: "WrongPassword123!"
        });

    assert.notEqual(existing.statusCode, 200);
    assert.notEqual(nonexistent.statusCode, 200);

    assert.equal(
        existing.statusCode,
        nonexistent.statusCode,
        "Existing and nonexistent accounts should use the same authentication failure status"
    );
});


test("wrong password does not reveal account existence in message", async () => {
    const existing = await request(app)
        .post("/api/auth/login")
        .send({
            email: existingEmail,
            password: "WrongPassword123!"
        });

    const nonexistent = await request(app)
        .post("/api/auth/login")
        .send({
            email: `unknown-${Date.now()}@example.com`,
            password: "WrongPassword123!"
        });

    const existingMessage =
        existing.body?.message ||
        existing.body?.error ||
        "";

    const nonexistentMessage =
        nonexistent.body?.message ||
        nonexistent.body?.error ||
        "";

    assert.equal(
        String(existingMessage).toLowerCase(),
        String(nonexistentMessage).toLowerCase(),
        "Authentication failure messages should not reveal account existence"
    );
});


test("nonexistent account does not return a JWT", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: `missing-${Date.now()}@example.com`,
            password
        });

    const token =
        response.body?.token ||
        response.body?.accessToken ||
        response.body?.data?.token ||
        response.body?.data?.accessToken;

    assert.equal(
        token,
        undefined,
        "Nonexistent account must not receive a JWT"
    );
});


test("empty email does not reveal account information", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "",
            password
        });

    assert.notEqual(
        response.statusCode,
        200
    );

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /user exists|account exists|registered user/i
    );
});


test("malformed email does not reveal account information", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "definitely-not-an-email",
            password
        });

    assert.notEqual(
        response.statusCode,
        200
    );

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /user exists|account exists|registered user/i
    );
});


test("email case differences do not reveal password state", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: existingEmail.toUpperCase(),
            password: "WrongPassword123!"
        });

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("unknown email with valid password cannot authenticate", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: `attacker-${Date.now()}@example.com`,
            password
        });

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("login failure does not expose database lookup details", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: `missing-db-${Date.now()}@example.com`,
            password: "WrongPassword123!"
        });

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /MongoServerError|Mongoose|CastError|MongoDB|collection|query/i,
        "Database details must not be exposed"
    );
});


test("login failure does not expose password comparison details", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: existingEmail,
            password: "WrongPassword123!"
        });

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /bcrypt|compare|hash|password hash|salt/i,
        "Password implementation details must not be exposed"
    );
});