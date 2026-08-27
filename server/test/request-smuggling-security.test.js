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

let token;

const registerAndLogin = async () => {
    const email = `smuggling-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Smuggling Test User",
            email,
            password
        });

    assert.ok(
        [200, 201, 409].includes(register.statusCode),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    const login = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });

    assert.equal(
        login.statusCode,
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
        `JWT token not returned: ${JSON.stringify(login.body)}`
    );

    return accessToken;
};

before(async () => {
    await startTestDatabase();
    token = await registerAndLogin();
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});


/*
 * 1. Normal authenticated request still works.
 *
 * This confirms the security checks did not break
 * normal HTTP request processing.
 */
test("normal authenticated request is accepted", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.statusCode,
        200,
        `Unexpected status: ${response.statusCode}`
    );
});


/*
 * 2. Invalid authentication cannot be bypassed
 * by Connection header manipulation.
 */
test("Connection header cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Connection", "keep-alive")
        .set("Authorization", "Bearer invalid-token");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 3. Multiple connection-related headers cannot
 * bypass authentication.
 */
test("connection header manipulation cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Connection", "close")
        .set("Authorization", "Bearer invalid-token");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 4. Authentication remains required on POST.
 */
test("POST request remains authentication protected", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .send({});

    assert.notEqual(
        response.statusCode,
        201
    );
});


/*
 * 5. Authentication remains required on DELETE.
 */
test("DELETE request remains authentication protected", async () => {
    const response = await request(app)
        .delete("/api/files/000000000000000000000000");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 6. Authentication remains required on share creation.
 */
test("share creation cannot bypass authentication", async () => {
    const response = await request(app)
        .post("/api/share/000000000000000000000000")
        .send({});

    assert.notEqual(
        response.statusCode,
        201
    );
});


/*
 * 7. Invalid Bearer token cannot bypass authentication.
 */
test("invalid bearer token cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "Bearer invalid.jwt.token");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 8. Basic authentication cannot be interpreted as
 * a Bearer JWT.
 */
test("Basic authorization cannot bypass JWT authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "Basic attacker-token");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 9. Empty authorization header cannot authenticate.
 */
test("empty authorization header is rejected", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "");

    assert.notEqual(
        response.statusCode,
        200
    );
});


/*
 * 10. Method override headers cannot change the
 * security boundary.
 */
test("method override header cannot bypass authorization", async () => {
    const response = await request(app)
        .post("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-HTTP-Method-Override", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200
    );
});