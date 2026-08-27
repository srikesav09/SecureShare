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
    const email =
        `csrf-state-${Date.now()}@example.com`;

    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "CSRF State User",
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


test("cross-site POST cannot create a share without authentication", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .post(`/api/share/${fakeFileId}`)
        .set("Origin", "https://evil.example.com")
        .send({});

    assert.notEqual(
        response.statusCode,
        201,
        "Unauthenticated cross-site request must not create a share"
    );
});


test("cross-site DELETE cannot delete a file without authentication", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeFileId}`)
        .set("Origin", "https://evil.example.com");

    assert.notEqual(
        response.statusCode,
        204,
        "Cross-site request must not delete a file"
    );
});


test("cross-site DELETE cannot revoke a share without authentication", async () => {
    const fakeShareId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/share/${fakeShareId}`)
        .set("Origin", "https://evil.example.com");

    assert.notEqual(
        response.statusCode,
        200,
        "Cross-site request must not revoke a share"
    );
});


test("malicious Origin cannot authorize authenticated file deletion", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeFileId}`)
        .set("Origin", "https://evil.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        204,
        "Malicious origin must not bypass authorization"
    );
});


test("malicious Origin cannot authorize authenticated share revocation", async () => {
    const fakeShareId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/share/${fakeShareId}`)
        .set("Origin", "https://evil.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        200,
        "Malicious origin must not bypass share authorization"
    );
});


test("malicious Referer cannot bypass authentication", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeFileId}`)
        .set(
            "Referer",
            "https://evil.example.com/attack"
        );

    assert.notEqual(
        response.statusCode,
        204
    );
});


test("forged X-Forwarded-Host cannot authorize a cross-site request", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeFileId}`)
        .set(
            "X-Forwarded-Host",
            "evil.example.com"
        )
        .set(
            "Origin",
            "https://evil.example.com"
        );

    assert.notEqual(
        response.statusCode,
        204
    );
});


test("CORS preflight does not authorize DELETE from malicious origin", async () => {
    const response = await request(app)
        .options("/api/files/507f1f77bcf86cd799439011")
        .set(
            "Origin",
            "https://evil.example.com"
        )
        .set(
            "Access-Control-Request-Method",
            "DELETE"
        )
        .set(
            "Access-Control-Request-Headers",
            "Authorization, Content-Type"
        );

    assert.notEqual(
        response.headers["access-control-allow-origin"],
        "https://evil.example.com"
    );
});


test("GET cannot be converted into a state-changing request using query parameters", async () => {
    const fakeFileId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .get(`/api/files/${fakeFileId}`)
        .query({
            method: "DELETE",
            action: "delete",
            userId: "attacker"
        })
        .set("Origin", "https://evil.example.com")
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.statusCode,
        204,
        "Query parameters must not change the HTTP operation"
    );
});


test("trusted origin remains available for legitimate authenticated API requests", async () => {
    const response = await request(app)
        .get("/api/files")
        .set(
            "Origin",
            "https://secureshare.srikesav.site"
        )
        .set(
            "Authorization",
            `Bearer ${token}`
        );

    assert.equal(
        response.headers["access-control-allow-origin"],
        "https://secureshare.srikesav.site"
    );
});