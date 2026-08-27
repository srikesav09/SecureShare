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
        `info-disclosure-${Date.now()}@example.com`;

    const password = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Information Test User",
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
        `No JWT returned: ${JSON.stringify(login.body)}`
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


test("unknown API route does not expose stack trace", async () => {
    const response = await request(app)
        .get("/api/this-route-does-not-exist");

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /at .*\.js:\d+|stack|stacktrace/i,
        "Stack trace must not be exposed"
    );
});


test("unknown API route does not expose filesystem paths", async () => {
    const response = await request(app)
        .get("/api/nonexistent-route");

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /C:\\|\/home\/|\/var\/|node_modules|src\\|src\//i,
        "Filesystem paths must not be exposed"
    );
});


test("malformed JSON does not expose parser internals", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('{"email":"broken",');

    assert.notEqual(
        response.statusCode,
        200
    );

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /SyntaxError|body-parser|express|stack/i,
        "Parser internals must not be exposed"
    );
});


test("invalid ObjectId does not expose MongoDB internals", async () => {
    const response = await request(app)
        .get("/api/files/not-a-valid-object-id")
        .set("Authorization", `Bearer ${token}`);

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /CastError|MongoServerError|Mongoose|MongoDB|ObjectId/i,
        "Database implementation details must not be exposed"
    );
});


test("invalid share ID does not expose database details", async () => {
    const response = await request(app)
        .delete("/api/share/not-a-valid-share-id")
        .set("Authorization", `Bearer ${token}`);

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /CastError|MongoServerError|Mongoose|MongoDB/i,
        "Database errors must not be exposed"
    );
});


test("authentication failure does not expose password details", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "unknown@example.com",
            password: "WrongPassword123!"
        });

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /bcrypt|argon|hash|salt|password hash/i,
        "Password implementation details must not be exposed"
    );
});


test("authentication failure does not expose user lookup details", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({
            email: "unknown@example.com",
            password: "WrongPassword123!"
        });

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /findOne|findById|mongoose|collection|query|database/i,
        "User lookup details must not be exposed"
    );
});


test("error response does not expose environment variables", async () => {
    const response = await request(app)
        .get("/api/nonexistent-route");

    const body = JSON.stringify(response.body);

    assert.doesNotMatch(
        body,
        /JWT_SECRET|MONGO_URI|DATABASE_URL|AWS_SECRET|PASSWORD=/i,
        "Environment secrets must not be exposed"
    );
});


test("error response does not expose authorization token", async () => {
    const response = await request(app)
        .get("/api/nonexistent-route")
        .set("Authorization", `Bearer ${token}`);

    const body = JSON.stringify(response.body);

    assert.equal(
        body.includes(token),
        false,
        "JWT must never appear in an error response"
    );
});


test("server does not expose Express identity through X-Powered-By", async () => {
    const response = await request(app)
        .get("/api/health");

    assert.equal(
        response.headers["x-powered-by"],
        undefined,
        "X-Powered-By header should not reveal Express"
    );
});