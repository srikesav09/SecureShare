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
        [200, 201].includes(register.statusCode),
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

    token =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.accessToken ||
        login.body?.data?.accessToken;

    assert.ok(
        token,
        `JWT token was not returned: ${JSON.stringify(login.body)}`
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


test("GET cannot be used to register a user", async () => {
    const response = await request(app)
        .get("/api/auth/register")
        .query({
            name: "Attacker",
            email: `attacker-${Date.now()}@example.com`,
            password: "StrongPassword123!"
        });

    assert.notEqual(response.statusCode, 200);
});


test("GET cannot be used to login", async () => {
    const response = await request(app)
        .get("/api/auth/login")
        .query({
            email: "attacker@example.com",
            password: "StrongPassword123!"
        });

    assert.notEqual(response.statusCode, 200);
});


test("GET cannot delete a file", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .get(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.statusCode, 204);
});


test("GET cannot revoke a share", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .get(`/api/share/${fakeId}`)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(response.statusCode, 204);
});


test("PUT cannot trigger file deletion", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .put(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            action: "delete"
        });

    assert.notEqual(response.statusCode, 204);
});


test("PATCH cannot trigger file deletion", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .patch(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            action: "delete"
        });

    assert.notEqual(response.statusCode, 204);
});


test("POST cannot be used as a file deletion method", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .post(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            action: "delete"
        });

    assert.notEqual(response.statusCode, 204);
});


test("POST cannot be used to revoke a share", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .post(`/api/share/${fakeId}`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            action: "revoke"
        });

    assert.notEqual(response.statusCode, 204);
});


test("unsupported HTTP method is rejected for file endpoint", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .patch(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`);

    assert.ok(
        [404, 405, 400, 401, 403].includes(response.statusCode),
        `Unexpected status: ${response.statusCode}`
    );
});


test("OPTIONS request cannot perform a state-changing operation", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .options(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${token}`);

    // CORS preflight may legitimately return 204.
    // The important security property is that OPTIONS
    // must not execute the protected DELETE operation.
    assert.ok(
        [200, 204, 404, 405].includes(response.statusCode),
        `Unexpected OPTIONS status: ${response.statusCode}`
    );

    assert.notEqual(
        response.headers["content-disposition"],
        'attachment',
        "OPTIONS must not execute the file operation"
    );
});