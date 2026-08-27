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

const registerAndLogin = async () => {
    const email = `jwt-security-${Date.now()}@example.com`;
    const password = "StrongPassword123!";
    

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "JWT Security User",
            email,
            password
        });

    assert.ok(
        [200, 201].includes(register.statusCode),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    user = register.body?.data?.user;

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
        `JWT token not returned: ${JSON.stringify(login.body)}`
    );

    return token;
};

before(async () => {
    await startTestDatabase();
    await registerAndLogin();
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});


test("valid JWT token authenticates the user", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.statusCode,
        200,
        `Valid JWT was rejected: ${JSON.stringify(response.body)}`
    );
});


test("tampered JWT signature is rejected", async () => {
    const parts = token.split(".");

    assert.equal(
        parts.length,
        3,
        "JWT must contain three parts"
    );

    const tamperedPayload =
        Buffer.from(
            JSON.stringify({
                id: user?._id || user?.id,
                role: "ADMIN"
            })
        ).toString("base64url");

    const tamperedToken =
        `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${tamperedToken}`);

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("malformed JWT is rejected", async () => {
    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            "Bearer this.is.not.a.valid.jwt.token"
        );

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("empty Bearer token is rejected", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", "Bearer ");

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("Basic authorization cannot authenticate as JWT", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Basic ${token}`);

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("JWT with modified signature is rejected", async () => {
    const parts = token.split(".");

    const modifiedSignature =
        parts[2].slice(0, -1) +
        (parts[2].endsWith("a") ? "b" : "a");

    const modifiedToken =
        `${parts[0]}.${parts[1]}.${modifiedSignature}`;

    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${modifiedToken}`);

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("expired JWT is rejected", async () => {
    const secret =
        process.env.JWT_SECRET ||
        process.env.ACCESS_TOKEN_SECRET;

    assert.ok(
        secret,
        "JWT secret is not configured in test environment"
    );

    const expiredToken = jwt.sign(
        {
            id: user?._id || user?.id,
            email: user?.email
        },
        secret,
        {
            expiresIn: -1
        }
    );

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${expiredToken}`
        );

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("JWT with forged admin role cannot bypass authorization", async () => {
    const parts = token.split(".");

    const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
    );

    payload.role = "ADMIN";
    payload.isAdmin = true;

    const forgedPayload =
        Buffer.from(
            JSON.stringify(payload)
        ).toString("base64url");

    const forgedToken =
        `${parts[0]}.${forgedPayload}.${parts[2]}`;

    const response = await request(app)
        .get("/api/admin")
        .set(
            "Authorization",
            `Bearer ${forgedToken}`
        );

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("JWT payload cannot be changed without invalidating signature", async () => {
    const parts = token.split(".");

    const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
    );

    payload.id = "000000000000000000000000";

    const modifiedPayload =
        Buffer.from(
            JSON.stringify(payload)
        ).toString("base64url");

    const modifiedToken =
        `${parts[0]}.${modifiedPayload}.${parts[2]}`;

    const response = await request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${modifiedToken}`
        );

    assert.notEqual(
        response.statusCode,
        200
    );
});


test("missing Authorization header is rejected", async () => {
    const response = await request(app)
        .get("/api/files");

    assert.notEqual(
        response.statusCode,
        200
    );
});