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


const PASSWORD =
    "TokenAbuseSecurity123!";

let user;
let token;
let email;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    email =
        `token-abuse-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Token Abuse User",

                email,

                password:
                    PASSWORD
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

                password:
                    PASSWORD
            });


    assert.equal(
        login.status,
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
        "Access token was not returned"
    );


    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(
        databaseUser
    );


    return {
        user:
            databaseUser,

        token:
            accessToken
    };
};


const authenticatedRequest = (
    jwtToken
) => {

    return request(app)
        .get("/api/files")
        .set(
            "Authorization",
            `Bearer ${jwtToken}`
        );
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    user =
        result.user;

    token =
        result.token;

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. VALID TOKEN
   ========================================================= */

test(
    "valid access token remains usable",
    async () => {

        const response =
            await authenticatedRequest(
                token
            );


        assert.notEqual(
            response.status,
            401
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   2. RANDOM TOKEN
   ========================================================= */

test(
    "random token is rejected",
    async () => {

        const response =
            await authenticatedRequest(
                "random-invalid-token"
            );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   3. EMPTY TOKEN
   ========================================================= */

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


/* =========================================================
   4. BASIC AUTH
   ========================================================= */

test(
    "basic authorization cannot replace access token",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Basic ${token}`
                );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   5. WRONG SIGNING SECRET
   ========================================================= */

test(
    "token signed with wrong secret is rejected",
    async () => {

        const secret =
            "wrong-token-secret";


        const forgedToken =
            jwt.sign(
                {
                    sub:
                        String(user.id),

                    id:
                        String(user.id)
                },
                secret,
                {
                    expiresIn:
                        "1h"
                }
            );


        const response =
            await authenticatedRequest(
                forgedToken
            );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   6. EXPIRED TOKEN
   ========================================================= */

test(
    "expired access token is rejected",
    async () => {

        const secret =
            process.env.JWT_SECRET ||
            process.env.ACCESS_TOKEN_SECRET ||
            process.env.JWT_SECRET_KEY;


        assert.ok(
            secret,
            "JWT secret is not configured"
        );


        const expiredToken =
            jwt.sign(
                {
                    sub:
                        String(user.id),

                    id:
                        String(user.id)
                },
                secret,
                {
                    expiresIn:
                        -10
                }
            );


        const response =
            await authenticatedRequest(
                expiredToken
            );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   7. NONE ALGORITHM
   ========================================================= */

test(
    "none algorithm token is rejected",
    async () => {

        const header =
            Buffer.from(
                JSON.stringify({
                    alg:
                        "none",

                    typ:
                        "JWT"
                })
            ).toString(
                "base64url"
            );


        const payload =
            Buffer.from(
                JSON.stringify({
                    sub:
                        String(user.id),

                    id:
                        String(user.id),

                    role:
                        "ADMIN"
                })
            ).toString(
                "base64url"
            );


        const forgedToken =
            `${header}.${payload}.`;


        const response =
            await authenticatedRequest(
                forgedToken
            );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   8. ROLE CLAIM CANNOT GRANT ADMIN
   ========================================================= */

test(
    "forged admin role cannot grant administrative access",
    async () => {

        const secret =
            process.env.JWT_SECRET ||
            process.env.ACCESS_TOKEN_SECRET ||
            process.env.JWT_SECRET_KEY;


        assert.ok(
            secret
        );


        const forgedToken =
            jwt.sign(
                {
                    sub:
                        String(user.id),

                    id:
                        String(user.id),

                    role:
                        "ADMIN",

                    isAdmin:
                        true
                },
                secret,
                {
                    expiresIn:
                        "1h"
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


/* =========================================================
   9. NONEXISTENT USER
   ========================================================= */

test(
    "token for deleted user is rejected",
    async () => {

        const secret =
            process.env.JWT_SECRET ||
            process.env.ACCESS_TOKEN_SECRET ||
            process.env.JWT_SECRET_KEY;


        assert.ok(
            secret
        );


        const forgedToken =
            jwt.sign(
                {
                    sub:
                        "507f1f77bcf86cd799439011",

                    id:
                        "507f1f77bcf86cd799439011"
                },
                secret,
                {
                    expiresIn:
                        "1h"
                }
            );


        const response =
            await authenticatedRequest(
                forgedToken
            );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   10. TOKEN CANNOT CHANGE IDENTITY
   ========================================================= */

test(
    "token payload modification invalidates authentication",
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


        payload.sub =
            "507f1f77bcf86cd799439011";


        payload.id =
            "507f1f77bcf86cd799439011";


        parts[1] =
            Buffer.from(
                JSON.stringify(
                    payload
                )
            ).toString(
                "base64url"
            );


        const modifiedToken =
            parts.join(".");


        const response =
            await authenticatedRequest(
                modifiedToken
            );


        assert.equal(
            response.status,
            401
        );

    }
);