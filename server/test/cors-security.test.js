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
    const email = `cors-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "CORS Security User",
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


test("trusted frontend origin is allowed by CORS", async () => {
    const response = await request(app)
        .get("/api/health")
        .set("Origin", "https://secureshare.srikesav.site");

    assert.equal(
        response.statusCode,
        200,
        `Health request failed: ${response.statusCode}`
    );

    assert.equal(
        response.headers["access-control-allow-origin"],
        "https://secureshare.srikesav.site"
    );
});


test("localhost development origin is allowed by CORS", async () => {
    const response = await request(app)
        .get("/api/health")
        .set("Origin", "http://localhost:5173");

    assert.equal(response.statusCode, 200);

    assert.equal(
        response.headers["access-control-allow-origin"],
        "http://localhost:5173"
    );
});


test("untrusted origin is not reflected by CORS", async () => {
    const response = await request(app)
        .get("/api/health")
        .set("Origin", "https://evil.example.com");

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://evil.example.com",
        "Untrusted origin must never be reflected"
    );
});


test("evil origin cannot receive authenticated CORS access", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Origin", "https://evil.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://evil.example.com"
    );
});


test("CORS does not use wildcard origin for authenticated requests", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Origin", "https://evil.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "*",
        "Authenticated API must not use wildcard CORS"
    );
});


test("malicious subdomain is not trusted", async () => {
    const response = await request(app)
        .get("/api/health")
        .set(
            "Origin",
            "https://secureshare.srikesav.site.evil.com"
        );

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://secureshare.srikesav.site.evil.com"
    );
});


test("lookalike domain is not trusted", async () => {
    const response = await request(app)
        .get("/api/health")
        .set(
            "Origin",
            "https://secureshare-srikesav.site"
        );

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://secureshare-srikesav.site"
    );
});


test("HTTP version of production origin is not trusted", async () => {
    const response = await request(app)
        .get("/api/health")
        .set("Origin", "http://secureshare.srikesav.site");

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "http://secureshare.srikesav.site"
    );
});


test("malicious origin cannot use authenticated file listing", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Origin", "https://attacker.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://attacker.example.com"
    );
});


test("CORS preflight does not approve malicious origin", async () => {
    const response = await request(app)
        .options("/api/files")
        .set("Origin", "https://evil.example.com")
        .set("Access-Control-Request-Method", "DELETE")
        .set(
            "Access-Control-Request-Headers",
            "Authorization, Content-Type"
        );

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://evil.example.com",
        "Malicious origin must not receive CORS permission"
    );
});