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
    const email = `cache-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Cache Security User",
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


test("authenticated file listing sends cache protection headers", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.statusCode, 200);

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.match(
        cacheControl,
        /no-store|no-cache/i,
        `Sensitive response should not be publicly cached: ${cacheControl}`
    );
});


test("authenticated response does not allow public caching", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i,
        `Authenticated data must not be publicly cached: ${cacheControl}`
    );
});


test("authenticated response does not expose sensitive data through ETag caching", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    const cacheControl =
        response.headers["cache-control"] || "";

    if (response.headers.etag) {
        assert.match(
            cacheControl,
            /no-store|no-cache/i,
            "ETag-protected authenticated data must have cache protection"
        );
    } else {
        assert.ok(true);
    }
});


test("login response is not publicly cacheable", async () => {
    const email = `cache-login-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    await request(app)
        .post("/api/auth/register")
        .send({
            name: "Cache Login User",
            email,
            password
        });

    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });

    assert.equal(response.statusCode, 200);

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i,
        "Login response must not be publicly cached"
    );
});


test("authenticated admin endpoint is not publicly cacheable", async () => {
    const response = await request(app)
        .get("/api/admin")
        .set("Authorization", `Bearer ${token}`);

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i
    );
});


test("unauthenticated protected response is not publicly cacheable", async () => {
    const response = await request(app)
        .get("/api/files");

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i
    );
});


test("file download response does not advertise public caching", async () => {
    const response = await request(app)
        .get("/api/files/000000000000000000000000/download")
        .set("Authorization", `Bearer ${token}`);

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i
    );
});


test("share creation response is not publicly cacheable", async () => {
    const response = await request(app)
        .post("/api/share/000000000000000000000000")
        .set("Authorization", `Bearer ${token}`)
        .send({});

    const cacheControl =
        response.headers["cache-control"] || "";

    assert.doesNotMatch(
        cacheControl,
        /public/i
    );
});


test("health endpoint remains accessible", async () => {
    const response = await request(app)
        .get("/api/health");

    assert.ok(
        [200, 204].includes(response.statusCode),
        `Unexpected health status: ${response.statusCode}`
    );
});


test("security headers remain present with caching protection", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.ok(
        response.headers["x-content-type-options"],
        "X-Content-Type-Options should be present"
    );

    assert.ok(
        response.headers["x-frame-options"] ||
        response.headers["content-security-policy"],
        "Clickjacking/content security protection should be present"
    );
});