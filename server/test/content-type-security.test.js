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
    const email = `content-type-${Date.now()}@example.com`;
    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Content Type User",
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


test("upload endpoint requires authentication", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Content-Type", "application/octet-stream")
        .send("test data");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("invalid JSON content type cannot bypass authentication", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Content-Type", "application/json")
        .send({
            filename: "test.txt"
        });

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("text content type cannot bypass multipart upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "text/plain")
        .send("malicious content");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("XML content type cannot bypass upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "application/xml")
        .send("<file>malicious</file>");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("JavaScript content type cannot bypass upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "application/javascript")
        .send("alert(1)");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("HTML content type cannot bypass upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "text/html")
        .send("<script>alert(1)</script>");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("fake multipart content type cannot bypass upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .set(
            "Content-Type",
            "multipart/form-data; boundary=invalid-boundary"
        )
        .send("fake multipart body");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("missing Content-Type does not bypass upload validation", async () => {
    const response = await request(app)
        .post("/api/files/upload")
        .set("Authorization", `Bearer ${token}`)
        .send("raw file data");

    assert.notEqual(
        response.statusCode,
        201
    );
});


test("file listing rejects unsupported content negotiation safely", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`)
        .set("Accept", "application/x-malicious-type");

    assert.equal(
        response.statusCode,
        200
    );

    assert.equal(
        response.headers["content-type"]?.includes("application/json"),
        true,
        `Expected JSON response, got ${response.headers["content-type"]}`
    );
});


test("API JSON response uses JSON content type", async () => {
    const response = await request(app)
        .get("/api/files")
        .set("Authorization", `Bearer ${token}`);

    assert.equal(
        response.statusCode,
        200
    );

    assert.match(
        response.headers["content-type"] || "",
        /^application\/json/i
    );
});