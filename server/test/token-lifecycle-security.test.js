import "./env.js";

import assert from "node:assert/strict";
import test, { before, after } from "node:test";
import request from "supertest";
import jwt from "jsonwebtoken";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

let token;
let user;

const password = "StrongPassword123!";

const registerAndLogin = async () => {
    const email =
        `token-lifecycle-${Date.now()}@example.com`;

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Token Lifecycle User",
            email,
            password
        });

    assert.ok(
        [200, 201].includes(register.statusCode),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    user =
        register.body?.data?.user ||
        register.body?.user;

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


test("valid JWT can access protected endpoint", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.statusCode,
        200,
        `Valid JWT rejected: ${JSON.stringify(response.body)}`
    );
});


test("missing Authorization header is rejected", async () => {
    const response = await request(app)
        .get("/api/files");

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Unexpected status: ${response.statusCode}`
    );
});


test("Bearer token with invalid signature is rejected", async () => {
    const parts = token.split(".");

    assert.equal(
        parts.length,
        3,
        "JWT should contain three segments"
    );

    const forgedToken =
        `${parts[0]}.${parts[1]}.invalidsignature`;

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${forgedToken}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Forged JWT was accepted: ${response.statusCode}`
    );
});


test("tampering with JWT payload is rejected", async () => {
    const parts = token.split(".");

    const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
    );

    payload.id =
        "507f1f77bcf86cd799439011";

    const modifiedPayload =
        Buffer.from(
            JSON.stringify(payload)
        ).toString("base64url");

    const tamperedToken =
        `${parts[0]}.${modifiedPayload}.${parts[2]}`;

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${tamperedToken}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Tampered JWT was accepted: ${response.statusCode}`
    );
});


test("expired JWT is rejected", async () => {
    const secret =
        process.env.JWT_SECRET ||
        process.env.ACCESS_TOKEN_SECRET;

    assert.ok(
        secret,
        "JWT secret must be configured for this test"
    );

    const expiredToken = jwt.sign(
        {
            id: user?.id || user?._id,
            email: user?.email,
            role: user?.role
        },
        secret,
        {
            expiresIn: -10
        }
    );

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${expiredToken}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Expired JWT was accepted: ${response.statusCode}`
    );
});


test("empty Bearer token is rejected", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "Bearer ");

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Empty Bearer token was accepted: ${response.statusCode}`
    );
});


test("Basic authentication scheme cannot replace Bearer", async () => {
    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Basic ${token}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Basic authentication unexpectedly accepted: ${response.statusCode}`
    );
});


test("duplicate Authorization headers cannot bypass authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            "Bearer invalid-token"
        )
        .set(
            "X-Authorization",
            `Bearer ${token}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Authentication header pollution may have bypassed security: ${response.statusCode}`
    );
});


test("JWT from attacker-controlled cookie cannot replace Bearer authentication", async () => {
    const response = await request(app)
        .get("/api/files")
        .set(
            "Cookie",
            "token=attacker-controlled-token"
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Cookie authentication unexpectedly succeeded: ${response.statusCode}`
    );
});


test("random JWT-like token is rejected", async () => {
    const randomToken = [
        Buffer.from(
            JSON.stringify({
                alg: "HS256",
                typ: "JWT"
            })
        ).toString("base64url"),

        Buffer.from(
            JSON.stringify({
                id: "507f1f77bcf86cd799439011",
                role: "ADMIN"
            })
        ).toString("base64url"),

        "attacker-controlled-signature"
    ].join(".");

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${randomToken}`
        );

    assert.ok(
        [401, 403].includes(response.statusCode),
        `Random JWT-like token was accepted: ${response.statusCode}`
    );
});