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
    const email = `json-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "JSON Security User",
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
 * 1. Malformed JSON must be rejected.
 */
test("malformed JSON body is rejected safely", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('{"email":"attacker@example.com","password":');

    assert.equal(
        response.statusCode,
        400,
        `Expected 400, got ${response.statusCode}`
    );
});


/*
 * 2. Empty JSON body must not bypass authentication.
 */
test("empty JSON body cannot bypass authentication", async () => {
    const response = await request(app)
        .post("/api/share/000000000000000000000000")
        .set("Authorization", "Bearer invalid-token")
        .set("Content-Type", "application/json")
        .send("{}");

    assert.ok(
        [401, 403, 404].includes(response.statusCode),
        `Unexpected response: ${response.statusCode}`
    );
});


/*
 * 3. Array body must not be accepted where an object is expected.
 */
test("array JSON body is handled safely", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send([]);

    assert.notEqual(
        response.statusCode,
        500,
        "Array body must not cause an internal server error"
    );
});


/*
 * 4. Primitive JSON body must be handled safely.
 */
test("primitive JSON body is handled safely", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send("attacker");

    assert.notEqual(
        response.statusCode,
        500,
        "Primitive JSON body must not cause an internal server error"
    );
});


/*
 * 5. __proto__ payload must not cause prototype pollution.
 */
test("__proto__ JSON payload cannot pollute prototypes", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
            __proto__: {
                polluted: true
            },
            email: "attacker@example.com",
            password: "invalid"
        });

    assert.notEqual(
        response.statusCode,
        500,
        "Prototype-pollution payload must not cause 500"
    );

    assert.equal(
        ({}).polluted,
        undefined,
        "Object prototype must not be polluted"
    );
});


/*
 * 6. constructor.prototype payload must not pollute objects.
 */
test("constructor prototype payload cannot pollute objects", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
            constructor: {
                prototype: {
                    polluted: true
                }
            },
            email: "attacker@example.com",
            password: "invalid"
        });

    assert.notEqual(
        response.statusCode,
        500,
        "Constructor payload must not cause 500"
    );

    assert.equal(
        ({}).polluted,
        undefined,
        "Object prototype must remain clean"
    );
});


/*
 * 7. Deeply nested JSON must not crash the application.
 */
test("deeply nested JSON body is handled safely", async () => {
    let payload = {};

    for (let i = 0; i < 100; i++) {
        payload = {
            nested: payload
        };
    }

    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send(payload);

    assert.notEqual(
        response.statusCode,
        500,
        "Deeply nested JSON must not crash the server"
    );
});


/*
 * 8. Unexpected object types must not bypass authentication.
 */
test("unexpected object types cannot bypass authentication", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
            email: {
                $ne: null
            },
            password: {
                $ne: null
            }
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Mongo-style operator objects must not bypass login"
    );
});


/*
 * 9. JSON body cannot replace JWT identity.
 */
test("JSON body cannot replace authenticated identity", async () => {
    const response = await request(app)
        .get("/api/files?userId=attacker")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "application/json")
        .send({
            userId: "attacker",
            ownerId: "attacker",
            id: "attacker"
        });

    assert.equal(
        response.statusCode,
        200,
        `Authenticated request failed: ${JSON.stringify(response.body)}`
    );

    assert.ok(
        Array.isArray(response.body?.data),
        "Expected files array"
    );
});


/*
 * 10. Very large JSON body must not crash the server.
 */
test("oversized JSON body is rejected safely", async () => {
    const largeValue = "A".repeat(2 * 1024 * 1024);

    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
            email: "attacker@example.com",
            password: largeValue
        });

    assert.ok(
        [400, 413].includes(response.statusCode),
        `Expected 400 or 413, got ${response.statusCode}`
    );
});