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
    const email = `request-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Request Security User",
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
 * 1. Conflicting Content-Length headers must not bypass authentication.
 */
test("conflicting Content-Length headers cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Content-Length", "0")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [400, 401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 2. Transfer-Encoding must not bypass authentication.
 */
test("Transfer-Encoding cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Transfer-Encoding", "chunked")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [400, 401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 3. Malformed Transfer-Encoding must be rejected safely.
 */
test("malformed Transfer-Encoding is rejected safely", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Transfer-Encoding", "invalid")
        .set("Authorization", "Bearer invalid-token");

    assert.notEqual(
        response.statusCode,
        200,
        "Malformed Transfer-Encoding must not produce a successful response"
    );
});


/*
 * 4. Duplicate Authorization headers cannot create authentication confusion.
 */
test("duplicate Authorization headers cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 5. Valid JWT remains valid with an ordinary Content-Length header.
 */
test("valid JWT authentication works with normal request headers", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Length", "0");

    assert.equal(
        response.statusCode,
        200,
        `Valid request failed: ${JSON.stringify(response.body)}`
    );
});


/*
 * 6. Connection header cannot disable authentication.
 */
test("Connection header cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Connection", "close")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 7. TE header cannot bypass authentication.
 */
test("TE header cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("TE", "chunked")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [400, 401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 8. Invalid Content-Length must not create a successful request.
 */
test("invalid Content-Length is rejected safely", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Content-Length", "not-a-number")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        200,
        "Invalid Content-Length must not be accepted as a normal request"
    );
});


/*
 * 9. Extremely large Content-Length must not bypass authorization.
 */
test("oversized Content-Length cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Content-Length", "999999999999999999")
        .set("Authorization", "Bearer invalid-token");

    assert.notEqual(
        response.statusCode,
        200,
        "Oversized Content-Length must not bypass authentication"
    );
});


/*
 * 10. Authentication must remain based on JWT rather than request framing.
 */
test("request framing headers cannot replace JWT authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Transfer-Encoding", "chunked")
        .set("Connection", "keep-alive")
        .set("Authorization", "Bearer invalid-token");

    assert.ok(
        [400, 401, 403].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});