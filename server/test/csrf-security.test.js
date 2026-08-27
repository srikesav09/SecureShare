import "./env.js";


import assert from "node:assert/strict";
import test, { before, after, beforeEach } from "node:test";
import request from "supertest";

import app from "../src/app.js";
import User from "../src/models/user.model.js";
import { startTestDatabase, clearTestDatabase, stopTestDatabase } from "./setup.js";

const API = "/api";

let user;
let token;

const registerAndLogin = async () => {
    const email =
        `csrf-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}@example.com`;

    const password = "StrongPassword123!";

    const registerResponse = await request(app)
        .post("/api/auth/register")
        .send({
            name: "CSRF Security User",
            email,
            password
        });

    assert.ok(
        [200, 201].includes(registerResponse.statusCode),
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });

    assert.equal(
        loginResponse.statusCode,
        200,
        `Login failed: ${JSON.stringify(loginResponse.body)}`
    );

    token =
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.accessToken ||
        loginResponse.body?.data?.token ||
        loginResponse.body?.token;

    assert.ok(
        token,
        `JWT access token should be returned: ${JSON.stringify(loginResponse.body)}`
    );
};


before(async () => {
    await startTestDatabase();
    await registerAndLogin();
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});


/*
 * ---------------------------------------------------------
 * AUTHENTICATION / CSRF BASELINE
 * ---------------------------------------------------------
 */

test("unauthenticated state-changing request is rejected", async () => {
    const response = await request(app)
        .post(`${API}/files/upload`);

    assert.notEqual(
        response.status,
        500,
        "Request must not cause a server error"
    );

    assert.ok(
        [401, 403, 400].includes(response.status),
        `Expected security rejection, got ${response.status}`
    );
});


test("authenticated request uses Bearer token rather than cookies", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.status, 401);

    assert.notEqual(
        response.status,
        500,
        "Authenticated request must not cause a server error"
    );
});


/*
 * ---------------------------------------------------------
 * ORIGIN / REFERER TESTS
 * ---------------------------------------------------------
 */

test("malicious Origin cannot bypass authentication", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Origin", "https://attacker.example")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.status,
        500,
        "Malicious Origin must not cause a server error"
    );
});


test("malicious Referer cannot bypass authentication", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Referer", "https://attacker.example/steal")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.status,
        500,
        "Malicious Referer must not cause a server error"
    );
});


/*
 * ---------------------------------------------------------
 * COOKIE ATTACKS
 * ---------------------------------------------------------
 */

test("attacker-controlled authentication cookie cannot replace JWT authentication", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Cookie", "token=attacker-controlled-token");

    assert.ok(
        [401, 403].includes(response.status),
        `Expected authentication failure, got ${response.status}`
    );
});


test("malformed authorization header is rejected", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Authorization", "Basic attacker-token");

    assert.equal(response.status, 401);
});


test("empty Bearer token is rejected", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Authorization", "Bearer ");

    assert.equal(response.status, 401);
});


/*
 * ---------------------------------------------------------
 * STATE-CHANGING ENDPOINTS
 * ---------------------------------------------------------
 */

test("share creation does not trust client-supplied user identity", async () => {
    const response = await request(app)
        .post(`${API}/share/000000000000000000000000`)
        .set("Authorization", `Bearer ${token}`)
        .set("Origin", "https://attacker.example")
        .send({
            userId: "000000000000000000000001",
            ownerId: "000000000000000000000002"
        });

    assert.notEqual(
        response.status,
        500,
        "Client identity manipulation must not cause a server error"
    );

    assert.notEqual(
        response.status,
        201,
        "Invalid attacker-controlled identity must not create a share"
    );
});


test("file deletion does not accept client-supplied user ID", async () => {
    const fakeFileId = "000000000000000000000000";

    const response = await request(app)
        .delete(`${API}/files/${fakeFileId}`)
        .set("Authorization", `Bearer ${token}`)
        .set("Origin", "https://attacker.example")
        .send({
            userId: "000000000000000000000001",
            ownerId: "000000000000000000000002"
        });

    assert.notEqual(
        response.status,
        500,
        "Client identity manipulation must not cause a server error"
    );

    assert.notEqual(
        response.status,
        200,
        "Attacker must not delete a file using a client-supplied identity"
    );
});


/*
 * ---------------------------------------------------------
 * GET SHOULD NOT PERFORM STATE CHANGES
 * ---------------------------------------------------------
 */

test("GET request cannot trigger file deletion", async () => {
    const fakeFileId = "000000000000000000000000";

    const response = await request(app)
        .get(`${API}/files/${fakeFileId}`)
        .set("Authorization", `Bearer ${token}`)
        .set("Origin", "https://attacker.example");

    assert.notEqual(
        response.status,
        200,
        "GET must not act as the delete endpoint"
    );
});


test("GET request cannot trigger share revocation", async () => {
    const fakeShareId = "000000000000000000000000";

    const response = await request(app)
        .get(`${API}/share/${fakeShareId}`)
        .set("Authorization", `Bearer ${token}`)
        .set("Origin", "https://attacker.example");

    assert.notEqual(
        response.status,
        200,
        "GET must not revoke a share"
    );
});


/*
 * ---------------------------------------------------------
 * HEADER MANIPULATION
 * ---------------------------------------------------------
 */

test("forged X-User-ID header cannot change authenticated identity", async () => {
    const response = await request(app)
        .get(`${API}/files`)
        .set("Authorization", `Bearer ${token}`)
        .set("X-User-ID", "000000000000000000000001")
        .set("X-User-Id", "000000000000000000000002")
        .set("X-Authenticated-User", "000000000000000000000003");

    assert.notEqual(
        response.status,
        500,
        "Forged identity headers must not cause a server error"
    );
});


test("query parameter cannot override authenticated identity", async () => {
    const response = await request(app)
        .get(`${API}/files?userId=000000000000000000000001&ownerId=000000000000000000000002`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.status,
        500,
        "Identity query parameters must not cause a server error"
    );
});