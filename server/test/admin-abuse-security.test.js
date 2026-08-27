import "./env.js";

import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import jwt from "jsonwebtoken";

import app from "../src/app.js";
import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const ADMIN_ENDPOINT = "/api/admin/audit-logs";
const TEST_PASSWORD = "TestPassword123!";

before(async () => {
    await startTestDatabase();
});

after(async () => {
    await stopTestDatabase();
});

async function registerAndLogin(role = "USER") {
    const email =
        `admin-security-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}@example.com`;

    const registerResponse = await request(app)
        .post("/api/auth/register")
        .send({
            name: role === "ADMIN" ? "Test Admin" : "Test User",
            email,
            password: TEST_PASSWORD
        });

    assert.equal(
        registerResponse.status,
        201,
        `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );

    const user = await User.findOne({ email });

    assert.ok(user, "Registered user was not found");

    if (role === "ADMIN") {
        user.role = "ADMIN";
        await user.save();
    }

    const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
            email,
            password: TEST_PASSWORD
        });

    assert.equal(
        loginResponse.status,
        200,
        `Login failed: ${JSON.stringify(loginResponse.body)}`
    );

    const token =
        loginResponse.body.token ||
        loginResponse.body.accessToken ||
        loginResponse.body.data?.token ||
        loginResponse.body.data?.accessToken;

    assert.ok(token, "JWT token was not returned");

    return {
        user,
        token
    };
}


// =====================================================
// 1. Unauthenticated request
// =====================================================

test("audit logs reject unauthenticated request", async () => {
    const response = await request(app)
        .get(ADMIN_ENDPOINT);

    assert.equal(response.status, 401);
});


// =====================================================
// 2. Normal user cannot access audit logs
// =====================================================

test("normal user cannot access audit logs", async () => {
    const { token } = await registerAndLogin("USER");

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 403);
});


// =====================================================
// 3. Client-side role manipulation
// =====================================================

test("changing client-side role does not grant admin access", async () => {
    const { user } = await registerAndLogin("USER");

    const modifiedToken = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: "ADMIN"
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "30m"
        }
    );

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${modifiedToken}`);

    assert.equal(response.status, 403);
});


// =====================================================
// 4. Invalid role
// =====================================================

test("invalid role does not grant admin privileges", async () => {
    const { user } = await registerAndLogin("USER");

    const token = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: "SUPERADMIN"
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "30m"
        }
    );

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 403);
});


// =====================================================
// 5. Lowercase admin role
// =====================================================

test("lowercase admin role does not bypass authorization", async () => {
    const { user } = await registerAndLogin("USER");

    const token = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: "admin"
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "30m"
        }
    );

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 403);
});


// =====================================================
// 6. Malformed Authorization header
// =====================================================

test("malformed authorization header cannot access audit logs", async () => {
    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", "InvalidToken");

    assert.equal(response.status, 401);
});


// =====================================================
// 7. Empty Bearer token
// =====================================================

test("empty bearer token cannot access audit logs", async () => {
    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", "Bearer ");

    assert.equal(response.status, 401);
});


// =====================================================
// 8. Query parameter bypass
// =====================================================

test("admin query parameters cannot bypass role check", async () => {
    const { token } = await registerAndLogin("USER");

    const response = await request(app)
        .get(`${ADMIN_ENDPOINT}?role=ADMIN&isAdmin=true`)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 403);
});


// =====================================================
// 9. Nonexistent user
// =====================================================

test("JWT for nonexistent user cannot access audit logs", async () => {
    const fakeUserId = "507f1f77bcf86cd799439011";

    const token = jwt.sign(
        {
            id: fakeUserId,
            email: "fake-admin@example.com",
            role: "ADMIN"
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "30m"
        }
    );

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${token}`);

    assert.equal(response.status, 401);
});


// =====================================================
// 10. Modified JWT signature
// =====================================================

test("modified JWT signature cannot grant admin access", async () => {
    const { token } = await registerAndLogin("USER");

    const parts = token.split(".");

    assert.equal(parts.length, 3);

    const modifiedToken =
        `${parts[0]}.${parts[1]}.${parts[2]}modified`;

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${modifiedToken}`);

    assert.equal(response.status, 401);
});


// =====================================================
// 11. Real admin access
// =====================================================

test("admin user can access audit logs", async () => {
    const { user, token } = await registerAndLogin("ADMIN");

    assert.equal(user.role, "ADMIN");

    const response = await request(app)
        .get(ADMIN_ENDPOINT)
        .set("Authorization", `Bearer ${token}`);

    assert.notEqual(
        response.status,
        401,
        `Admin authentication failed: ${JSON.stringify(response.body)}`
    );

    assert.notEqual(
        response.status,
        403,
        `Admin authorization failed: ${JSON.stringify(response.body)}`
    );
});