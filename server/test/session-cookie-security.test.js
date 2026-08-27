import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert/strict";
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
        `cookie-security-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}@example.com`;

    const password =
        "StrongPassword123!";


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Cookie Security User",
                email,
                password
            });

    assert.ok(
        [200, 201].includes(register.status),
        `Registration failed: ${JSON.stringify(register.body)}`
    );


    const login =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,
                password
            });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );


    const accessToken =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;

    assert.ok(
        accessToken,
        `Access token missing: ${JSON.stringify(login.body)}`
    );

    return accessToken;
};


before(async () => {

    await startTestDatabase();

    // Login only once.
    token = await registerAndLogin();

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * 1. LOGIN SHOULD NOT EXPOSE PASSWORD
 * =========================================================
 */

test(
    "login response does not expose password",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email:
                        "cookie-security-test@example.com",
                    password:
                        "wrong-password"
                });


        const body =
            JSON.stringify(response.body)
                .toLowerCase();


        assert.equal(
            body.includes("passwordhash"),
            false
        );

    }
);


/*
 * =========================================================
 * 2. AUTHENTICATION SHOULD USE BEARER TOKEN
 * =========================================================
 */

test(
    "authentication is not granted by arbitrary cookies",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Cookie",
                    "token=fake-admin-token"
                );


        assert.ok(
            [401, 403].includes(response.status),
            `Unexpected status: ${response.status}`
        );

    }
);


/*
 * =========================================================
 * 3. FAKE SESSION COOKIE CANNOT AUTHENTICATE
 * =========================================================
 */

test(
    "fake session cookie cannot authenticate a user",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Cookie",
                    "session=administrator"
                );


        assert.ok(
            [401, 403].includes(response.status),
            `Fake session authenticated the request: ${response.status}`
        );

    }
);


/*
 * =========================================================
 * 4. INVALID AUTH COOKIE CANNOT BYPASS JWT
 * =========================================================
 */

test(
    "invalid authentication cookie cannot bypass JWT authentication",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Cookie",
                    "auth=valid-looking-but-fake-token"
                );


        assert.ok(
            [401, 403].includes(response.status)
        );

    }
);


/*
 * =========================================================
 * 5. COOKIE VALUE CANNOT BECOME ADMIN
 * =========================================================
 */

test(
    "cookie role cannot grant administrator privileges",
    async () => {

        const response =
            await request(app)
                .get("/api/admin/audit-logs")
                .set(
                    "Cookie",
                    "role=ADMIN;userRole=ADMIN"
                );


        assert.ok(
            [401, 403].includes(response.status),
            `Cookie granted admin access: ${response.status}`
        );

    }
);


/*
 * =========================================================
 * 6. MALFORMED COOKIE CANNOT CRASH SERVER
 * =========================================================
 */

test(
    "malformed cookie is rejected safely",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Cookie",
                    "session=%00%00%00; token={{{{"
                );


        assert.notEqual(
            response.status,
            500,
            "Malformed cookie caused server error"
        );

    }
);


/*
 * =========================================================
 * 7. COOKIE CANNOT REPLACE AUTHORIZATION HEADER
 * =========================================================
 */

test(
    "fake cookie cannot override a valid Bearer identity",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Cookie",
                    "userId=attacker;role=ADMIN"
                );


        assert.notEqual(
            response.status,
            401,
            "Cookie incorrectly replaced valid JWT authentication"
        );

    }
);


/*
 * =========================================================
 * 8. MULTIPLE COOKIE VALUES CANNOT GRANT ADMIN
 * =========================================================
 */

test(
    "duplicate cookie identity values cannot grant privileges",
    async () => {

        const response =
            await request(app)
                .get("/api/admin/audit-logs")
                .set(
                    "Cookie",
                    "role=USER;role=ADMIN;userId=attacker"
                );


        assert.ok(
            [401, 403].includes(response.status),
            `Duplicate cookie values bypassed authorization: ${response.status}`
        );

    }
);


/*
 * =========================================================
 * 9. COOKIE HEADER INJECTION IS REJECTED
 * =========================================================
 */

test(
    "cookie header injection is rejected safely",
    async () => {

        let response;

        try {

            response =
                await request(app)
                    .get("/api/files")
                    .set(
                        "Cookie",
                        "session=abc\r\nX-Injected: true"
                    );

        } catch (error) {

            /*
             * Node may reject malformed headers before
             * the request reaches Express.
             *
             * That is safe behaviour.
             */
            assert.ok(error);

            return;
        }


        assert.notEqual(
            response.status,
            500
        );

    }
);


/*
 * =========================================================
 * 10. AUTHORIZATION HEADER REMAINS AUTHORITATIVE
 * =========================================================
 */

test(
    "valid JWT remains authoritative when unrelated cookies are supplied",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "Cookie",
                    "userId=attacker;role=ADMIN;session=fake"
                );


        assert.notEqual(
            response.status,
            401,
            "Cookies incorrectly replaced JWT authentication"
        );

    }
);