import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

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


// =========================================================
// CONSTANTS
// =========================================================

const PASSWORD = "SessionPassword123!";

const JWT_SECRET =
    process.env.JWT_SECRET ||
    process.env.ACCESS_TOKEN_SECRET ||
    process.env.JWT_SECRET_KEY;


// =========================================================
// HELPERS
// =========================================================

const uniqueEmail = (prefix = "session") =>
    `${prefix}-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 10)}@example.com`;


const createUserAndLogin = async () => {

    const email =
        uniqueEmail();

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Session Security User",
                email,
                password: PASSWORD
            });

    assert.equal(
        register.status,
        201,
        `Registration failed: ${JSON.stringify(register.body)}`
    );


    const login =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password: PASSWORD
            });


    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );


    const token =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;


    assert.ok(
        token,
        `JWT token was not returned: ${JSON.stringify(login.body)}`
    );


    const user =
        await User.findOne({
            email
        });


    assert.ok(
        user,
        "User was not found"
    );


    return {
        email,
        token,
        user
    };
};


const authRequest = (token) =>
    request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${token}`
        );


// =========================================================
// DATABASE SETUP
// =========================================================

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();

});


after(async () => {

    await stopTestDatabase();

});


// =========================================================
// 1. VALID TOKEN
// =========================================================

test(
    "valid JWT authenticates the correct user",
    async () => {

        const {
            token
        } =
            await createUserAndLogin();


        const response =
            await authRequest(token);


        assert.notEqual(
            response.status,
            401
        );

    }
);


// =========================================================
// 2. MISSING TOKEN
// =========================================================

test(
    "request without JWT is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files");


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 3. EMPTY TOKEN
// =========================================================

test(
    "empty Bearer token is rejected",
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


// =========================================================
// 4. INVALID TOKEN
// =========================================================

test(
    "random invalid JWT is rejected",
    async () => {

        const response =
            await authRequest(
                "this-is-not-a-jwt"
            );


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 5. WRONG SECRET
// =========================================================

test(
    "JWT signed using wrong secret is rejected",
    async () => {

        const {
            user
        } =
            await createUserAndLogin();


        const forgedToken =
            jwt.sign(
                {
                    sub: user.id.toString(),
                    id: user.id.toString()
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


// =========================================================
// 6. EXPIRED TOKEN
// =========================================================

test(
    "expired JWT is rejected",
    async () => {

        const {
            user
        } =
            await createUserAndLogin();


        const expiredToken =
            jwt.sign(
                {
                    sub: user.id.toString(),
                    id: user.id.toString()
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


// =========================================================
// 7. NONE ALGORITHM
// =========================================================

test(
    "JWT none algorithm is rejected",
    async () => {

        const {
            user
        } =
            await createUserAndLogin();


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
                    sub: user.id.toString(),
                    id: user.id.toString()
                })
            ).toString("base64url");


        const token =
            `${header}.${payload}.`;


        const response =
            await authRequest(token);


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 8. TAMPERED PAYLOAD
// =========================================================

test(
    "tampering with JWT payload invalidates the token",
    async () => {

        const {
            token
        } =
            await createUserAndLogin();


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


// =========================================================
// 9. BASIC AUTH CANNOT REPLACE JWT
// =========================================================

test(
    "Basic authentication cannot replace JWT",
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


// =========================================================
// 10. BEARER FORMAT
// =========================================================

test(
    "malformed Bearer authorization is rejected",
    async () => {

        const malformedTokens = [
            "Bearer",
            "Bearer.",
            "Token attacker",
            "JWT attacker",
            "Basic attacker",
            "attacker-token"
        ];


        for (const authorization of malformedTokens) {

            const response =
                await request(app)
                    .get("/api/files")
                    .set(
                        "Authorization",
                        authorization
                    );


            assert.equal(
                response.status,
                401,
                `Malformed authorization was accepted: ${authorization}`
            );

        }

    }
);


// =========================================================
// 11. NONEXISTENT USER
// =========================================================

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


// =========================================================
// 12. MISSING SUB
// =========================================================

test(
    "JWT without sub claim is rejected",
    async () => {

        const token =
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
            await authRequest(token);


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 13. MISSING IDENTITY
// =========================================================

test(
    "JWT without identity claims is rejected",
    async () => {

        const token =
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
            await authRequest(token);


        assert.equal(
            response.status,
            401
        );

    }
);


// =========================================================
// 14. ROLE CLAIM CANNOT ESCALATE
// =========================================================

test(
    "client-controlled ADMIN role claim cannot grant privileges",
    async () => {

        const {
            user
        } =
            await createUserAndLogin();


        const forgedToken =
            jwt.sign(
                {
                    sub: user.id.toString(),
                    id: user.id.toString(),
                    role: "ADMIN"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );


        const response =
            await request(app)
                .get("/api/admin/audit-logs")
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


// =========================================================
// 15. LOWERCASE ADMIN
// =========================================================

test(
    "lowercase admin role claim cannot grant privileges",
    async () => {

        const {
            user
        } =
            await createUserAndLogin();


        const forgedToken =
            jwt.sign(
                {
                    sub: user.id.toString(),
                    id: user.id.toString(),
                    role: "admin"
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );


        const response =
            await request(app)
                .get("/api/admin/audit-logs")
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