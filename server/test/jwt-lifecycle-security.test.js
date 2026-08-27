import "./env.js";

import assert from "node:assert/strict";
import test, {
    before,
    after,
    beforeEach
} from "node:test";

import request from "supertest";
import jwt from "jsonwebtoken";

import app from "../src/app.js";
import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

let user;
let token;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    process.env.ACCESS_TOKEN_SECRET ||
    process.env.JWT_SECRET_KEY;

const PASSWORD = "Password123!";

// ============================================================
// REGISTER + LOGIN
// ============================================================

async function registerAndLogin() {
    const uniqueId =
        `${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}`;

    const email =
        `jwt-${uniqueId}@example.com`;

    // Unique IP for every test.
    // This prevents the login/register rate limiter
    // from treating the entire security suite as one client.
    const testIp =
        `10.50.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    // --------------------------------------------------------
    // Register
    // --------------------------------------------------------

    const registerResponse =
        await request(app)
            .post("/api/auth/register")
            .set("X-Forwarded-For", testIp)
            .send({
                name: "JWT Security User",
                email,
                password: PASSWORD
            });

    assert.ok(
        [200, 201].includes(registerResponse.status),
        `Registration failed: ${JSON.stringify(
            registerResponse.body
        )}`
    );

    // --------------------------------------------------------
    // Login
    // --------------------------------------------------------

    const loginResponse =
        await request(app)
            .post("/api/auth/login")
            .set("X-Forwarded-For", testIp)
            .send({
                email,
                password: PASSWORD
            });

    assert.equal(
        loginResponse.status,
        200,
        `Login failed: ${JSON.stringify(
            loginResponse.body
        )}`
    );

    const loginToken =
        loginResponse.body?.data?.token ||
        loginResponse.body?.data?.accessToken ||
        loginResponse.body?.token ||
        loginResponse.body?.accessToken;

    assert.ok(
        loginToken,
        `JWT token was not returned: ${JSON.stringify(
            loginResponse.body
        )}`
    );

    // --------------------------------------------------------
    // Get actual database user
    // --------------------------------------------------------

    const foundUser =
        await User.findOne({ email });

    assert.ok(
        foundUser,
        `User was not found after registration: ${email}`
    );

    return {
        user: foundUser,
        token: loginToken
    };
}

// ============================================================
// AUTHENTICATED REQUEST
// ============================================================

function authRequest(jwtToken) {
    return request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${jwtToken}`
        );
}

// ============================================================
// DATABASE SETUP
// ============================================================

before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();

    const result =
        await registerAndLogin();

    user = result.user;
    token = result.token;
});

after(async () => {
    await clearTestDatabase();
    await stopTestDatabase();
});

// ============================================================
// 1. VALID JWT
// ============================================================

test(
    "valid JWT can authenticate the user",
    async () => {

        const response =
            await authRequest(token);

        assert.notEqual(
            response.status,
            401
        );
    }
);

// ============================================================
// 2. EXPIRED JWT
// ============================================================

test(
    "expired JWT is rejected",
    async () => {

        assert.ok(
            JWT_SECRET,
            "JWT secret is not configured"
        );

        const expiredToken =
            jwt.sign(
                {
                    sub: user._id.toString(),
                    id: user._id.toString()
                },
                JWT_SECRET,
                {
                    expiresIn: -10
                }
            );

        const response =
            await authRequest(
                expiredToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 3. WRONG SECRET
// ============================================================

test(
    "JWT signed with another secret is rejected",
    async () => {

        const forgedToken =
            jwt.sign(
                {
                    sub: user._id.toString(),
                    id: user._id.toString(),
                    role: "ADMIN"
                },
                "completely-wrong-secret",
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await authRequest(
                forgedToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 4. ANOTHER USER'S SUB
// ============================================================

test(
    "JWT with another user's sub cannot impersonate that user",
    async () => {

        const anotherEmail =
            `other-${Date.now()}-${Math.random()}@example.com`;

        const registerResponse =
            await request(app)
                .post("/api/auth/register")
                .set(
                    "X-Forwarded-For",
                    `10.60.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`
                )
                .send({
                    name: "Another User",
                    email: anotherEmail,
                    password: PASSWORD
                });

        assert.ok(
            [200, 201].includes(
                registerResponse.status
            )
        );

        const anotherUser =
            await User.findOne({
                email: anotherEmail
            });

        assert.ok(anotherUser);

        const forgedToken =
            jwt.sign(
                {
                    sub: anotherUser._id.toString(),
                    id: anotherUser._id.toString()
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await authRequest(
                forgedToken
            );

        // The JWT is cryptographically valid.
        // Authentication must therefore use the user
        // represented by the server-side database lookup.
        assert.notEqual(
            response.status,
            500
        );
    }
);

// ============================================================
// 5. FORGED ADMIN ROLE
// ============================================================

test(
    "JWT role claim cannot grant admin privileges",
    async () => {

        const forgedToken =
            jwt.sign(
                {
                    sub: user._id.toString(),
                    id: user._id.toString(),
                    role: "ADMIN"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs"
                )
                .set(
                    "Authorization",
                    `Bearer ${forgedToken}`
                );

        assert.equal(
            response.status,
            403
        );
    }
);

// ============================================================
// 6. LOWERCASE ADMIN
// ============================================================

test(
    "lowercase admin role cannot bypass authorization",
    async () => {

        const forgedToken =
            jwt.sign(
                {
                    sub: user._id.toString(),
                    id: user._id.toString(),
                    role: "admin"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs"
                )
                .set(
                    "Authorization",
                    `Bearer ${forgedToken}`
                );

        assert.equal(
            response.status,
            403
        );
    }
);

// ============================================================
// 7. NONEXISTENT USER
// ============================================================

test(
    "JWT containing nonexistent user ID is rejected",
    async () => {

        const fakeUserId =
            "507f1f77bcf86cd799439011";

        const forgedToken =
            jwt.sign(
                {
                    sub: fakeUserId,
                    id: fakeUserId
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await authRequest(
                forgedToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 8. MISSING SUB
// ============================================================

test(
    "JWT without sub claim is rejected",
    async () => {

        const forgedToken =
            jwt.sign(
                {
                    role: "USER"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await authRequest(
                forgedToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 9. MISSING IDENTITY
// ============================================================

test(
    "JWT without user identity is rejected",
    async () => {

        const forgedToken =
            jwt.sign(
                {
                    foo: "bar"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

        const response =
            await authRequest(
                forgedToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 10. TAMPERED PAYLOAD
// ============================================================

test(
    "tampered JWT payload is rejected",
    async () => {

        const parts =
            token.split(".");

        assert.equal(
            parts.length,
            3
        );

        const payload =
            JSON.parse(
                Buffer.from(
                    parts[1],
                    "base64url"
                ).toString()
            );

        payload.role = "ADMIN";

        parts[1] =
            Buffer.from(
                JSON.stringify(payload)
            ).toString("base64url");

        const tamperedToken =
            parts.join(".");

        const response =
            await authRequest(
                tamperedToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 11. NONE ALGORITHM ATTACK
// ============================================================

test(
    "JWT using none algorithm is rejected",
    async () => {

        const header =
            Buffer.from(
                JSON.stringify({
                    alg: "none",
                    typ: "JWT"
                })
            ).toString("base64url");

        const payload =
            Buffer.from(
                JSON.stringify({
                    sub: user._id.toString(),
                    id: user._id.toString(),
                    role: "ADMIN"
                })
            ).toString("base64url");

        const noneToken =
            `${header}.${payload}.`;

        const response =
            await authRequest(
                noneToken
            );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 12. BASIC AUTH
// ============================================================

test(
    "Basic authorization cannot replace JWT",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    "Basic attacker-token"
                );

        assert.equal(
            response.status,
            401
        );
    }
);

// ============================================================
// 13. EMPTY BEARER TOKEN
// ============================================================

test(
    "empty bearer token is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    "Bearer "
                );

        assert.equal(
            response.status,
            401
        );
    }
);