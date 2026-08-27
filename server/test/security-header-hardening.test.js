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
    const email = `headers-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Header Security User",
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


test("X-Powered-By header is disabled", async () => {
    const response = await request(app)
        .get("/api/health");

    assert.equal(
        response.headers["x-powered-by"],
        undefined
    );
});


test("X-Content-Type-Options prevents MIME sniffing", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.headers["x-content-type-options"],
        "nosniff"
    );
});


test("X-Frame-Options prevents clickjacking", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.ok(
        response.headers["x-frame-options"] ||
        response.headers["content-security-policy"]?.includes(
            "frame-ancestors"
        ),
        "Clickjacking protection header is missing"
    );
});


test("Strict-Transport-Security is enabled", async () => {
    const response = await request(app)
        .get("/api/health");

    const hsts =
        response.headers["strict-transport-security"];

    assert.ok(
        hsts,
        "HSTS header is missing"
    );

    assert.match(
        hsts,
        /max-age=\d+/i
    );
});


test("HSTS includes subdomains", async () => {
    const response = await request(app)
        .get("/api/health");

    const hsts =
        response.headers["strict-transport-security"] || "";

    assert.match(
        hsts,
        /includesubdomains/i,
        `HSTS should include subdomains: ${hsts}`
    );
});


test("Referrer-Policy header is present", async () => {
    const response = await request(app)
        .get("/api/health");

    assert.ok(
        response.headers["referrer-policy"],
        "Referrer-Policy header is missing"
    );
});


test("Content-Security-Policy is not accidentally weakened", async () => {
    const response = await request(app)
        .get("/api/health");

    const csp =
        response.headers["content-security-policy"];

    /*
     * Your current application explicitly disables Helmet CSP,
     * so this test verifies that if CSP is present it isn't
     * configured with an unrestricted wildcard.
     */
    if (csp) {
        assert.doesNotMatch(
            csp,
            /default-src\s+\*/i,
            "CSP must not use unrestricted default-src *"
        );
    } else {
        assert.ok(true);
    }
});


test("authenticated API responses retain security headers", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.headers["x-content-type-options"],
        "nosniff"
    );

    assert.ok(
        response.headers["x-frame-options"] ||
        response.headers["content-security-policy"]?.includes(
            "frame-ancestors"
        )
    );
});


test("security headers are present on authentication responses", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "nonexistent-header-test@example.com",
            password: "WrongPassword123!"
        });

    assert.ok(
        response.headers["x-content-type-options"],
        "MIME sniffing protection missing"
    );

    assert.ok(
        response.headers["x-frame-options"] ||
        response.headers["content-security-policy"],
        "Clickjacking protection missing"
    );
});


test("security headers remain present on invalid routes", async () => {
    const response = await request(app)
        .get("/api/this-route-does-not-exist");

    assert.equal(
        response.statusCode,
        404
    );

    assert.equal(
        response.headers["x-content-type-options"],
        "nosniff"
    );

    assert.ok(
        response.headers["x-frame-options"] ||
        response.headers["content-security-policy"]
    );
});
