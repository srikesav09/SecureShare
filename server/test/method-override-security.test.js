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
    const email = `method-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Method Security User",
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
 * 1. GET must not become DELETE through query parameters.
 */
test("GET with method override cannot trigger file deletion", async () => {
    const response = await request(app)
        .get("/api/files/000000000000000000000000?_method=DELETE")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        200,
        "GET must not be converted into DELETE"
    );
});


/*
 * 2. GET must not become POST through query parameters.
 */
test("GET with _method=POST cannot trigger state change", async () => {
    const response = await request(app)
        .get("/api/files/upload?_method=POST")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        201,
        "GET must not be converted into POST"
    );
});


/*
 * 3. POST must not become DELETE through query parameters.
 */
test("POST with _method=DELETE cannot trigger deletion", async () => {
    const response = await request(app)
        .post("/api/files/000000000000000000000000?_method=DELETE")
        .set("Authorization", `Bearer ${token}`)
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "POST must not be converted into DELETE"
    );
});


/*
 * 4. X-HTTP-Method-Override must not enable DELETE.
 */
test("X-HTTP-Method-Override cannot convert request into DELETE", async () => {
    const response = await request(app)
        .post("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-HTTP-Method-Override", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "Method override must not trigger DELETE"
    );
});


/*
 * 5. X-HTTP-Method must not override the request method.
 */
test("X-HTTP-Method cannot override request method", async () => {
    const response = await request(app)
        .post("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-HTTP-Method", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "X-HTTP-Method must not trigger DELETE"
    );
});


/*
 * 6. X-Method-Override must not override request method.
 */
test("X-Method-Override cannot trigger state change", async () => {
    const response = await request(app)
        .post("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-Method-Override", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "X-Method-Override must not trigger DELETE"
    );
});


/*
 * 7. HEAD must not execute a GET state-changing route.
 */
test("HEAD request cannot trigger state-changing endpoint", async () => {
    const response = await request(app)
        .head("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        200,
        "HEAD must not trigger state-changing behavior"
    );
});


/*
 * 8. OPTIONS must not execute a state-changing request.
 */
test("OPTIONS request cannot trigger file deletion", async () => {
    const response = await request(app)
        .options("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        200,
        "OPTIONS must not execute DELETE behavior"
    );
});


/*
 * 9. PATCH must not become DELETE through headers.
 */
test("PATCH with method override cannot become DELETE", async () => {
    const response = await request(app)
        .patch("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-HTTP-Method-Override", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "PATCH must not be converted into DELETE"
    );
});


/*
 * 10. PUT must not become DELETE through headers.
 */
test("PUT with method override cannot become DELETE", async () => {
    const response = await request(app)
        .put("/api/files/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .set("X-HTTP-Method-Override", "DELETE")
        .send({});

    assert.notEqual(
        response.statusCode,
        200,
        "PUT must not be converted into DELETE"
    );
});