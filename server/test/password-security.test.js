import "./env.js";

import assert from "node:assert/strict";
import test, {
    before,
    after,
    beforeEach
} from "node:test";

import request from "supertest";
import bcrypt from "bcrypt";

import app from "../src/app.js";
import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const PASSWORD = "Password123!";

let user;
let email;

const uniqueEmail = () =>
    `password-${Date.now()}-${Math.random()}@example.com`;

async function registerUser({
    name = "Password Test User",
    email: userEmail = uniqueEmail(),
    password = PASSWORD
} = {}) {
    return request(app)
        .post("/api/auth/register")
        .send({
            name,
            email: userEmail,
            password
        });
}

async function loginUser(
    userEmail,
    password
) {
    return request(app)
        .post("/api/auth/login")
        .send({
            email: userEmail,
            password
        });
}

before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();

    email = uniqueEmail();

    const response =
        await registerUser({
            email
        });

    assert.equal(
        response.status,
        201,
        `Registration failed: ${JSON.stringify(
            response.body
        )}`
    );

    user = await User.findOne({
        email
    });

    assert.ok(user);
});

after(async () => {
    await stopTestDatabase();
});


// ============================================================
// 1. Valid password works
// ============================================================

test(
    "valid password allows login",
    async () => {
        const response =
            await loginUser(
                email,
                PASSWORD
            );

        assert.equal(
            response.status,
            200,
            JSON.stringify(response.body)
        );

        assert.ok(
            response.body?.data?.token
        );
    }
);


// ============================================================
// 2. Wrong password rejected
// ============================================================

test(
    "incorrect password is rejected",
    async () => {
        const response =
            await loginUser(
                email,
                "WrongPassword123!"
            );

        assert.equal(
            response.status,
            401
        );
    }
);


// ============================================================
// 3. Empty password
// ============================================================

test(
    "empty password is rejected",
    async () => {
        const response =
            await loginUser(
                email,
                ""
            );

        assert.notEqual(
            response.status,
            200
        );
    }
);


// ============================================================
// 4. Missing password
// ============================================================

test(
    "missing password is rejected",
    async () => {
        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    email
                });

        assert.notEqual(
            response.status,
            200
        );
    }
);


// ============================================================
// 5. Missing email
// ============================================================

test(
    "missing email is rejected",
    async () => {
        const response =
            await request(app)
                .post("/api/auth/login")
                .send({
                    password: PASSWORD
                });

        assert.notEqual(
            response.status,
            200
        );
    }
);


// ============================================================
// 6. Nonexistent account cannot login
// ============================================================

test(
    "nonexistent account cannot login",
    async () => {
        const response =
            await loginUser(
                "does-not-exist@example.com",
                PASSWORD
            );

        assert.equal(
            response.status,
            401
        );
    }
);


// ============================================================
// 7. Duplicate email registration
// ============================================================

test(
    "duplicate email registration is rejected",
    async () => {
        const response =
            await registerUser({
                email,
                password: "AnotherPassword123!"
            });

        assert.notEqual(
            response.status,
            201
        );

        assert.ok(
            response.status >= 400
        );
    }
);


// ============================================================
// 8. Password is not stored as plaintext
// ============================================================

test(
    "password is not stored as plaintext",
    async () => {
        assert.ok(user.password);

        assert.notEqual(
            user.password,
            PASSWORD
        );

        assert.ok(
            user.password.length >= 50
        );
    }
);


// ============================================================
// 9. Stored password verifies with bcrypt
// ============================================================

test(
    "stored password is a valid bcrypt hash",
    async () => {
        const valid =
            await bcrypt.compare(
                PASSWORD,
                user.password
            );

        assert.equal(
            valid,
            true
        );
    }
);


// ============================================================
// 10. API never returns password
// ============================================================

test(
    "registration response does not expose password",
    async () => {
        const response =
            await registerUser({
                email: uniqueEmail()
            });

        assert.equal(
            response.status,
            201
        );

        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();

        assert.ok(
            !body.includes(PASSWORD.toLowerCase())
        );

        assert.ok(
            !response.body?.data?.password
        );
    }
);


// ============================================================
// 11. Login response does not expose password
// ============================================================

test(
    "login response does not expose password",
    async () => {
        const response =
            await loginUser(
                email,
                PASSWORD
            );

        assert.equal(
            response.status,
            200
        );

        const body =
            JSON.stringify(
                response.body
            ).toLowerCase();

        assert.ok(
            !body.includes(
                PASSWORD.toLowerCase()
            )
        );

        assert.ok(
            !response.body?.data?.password
        );
    }
);


// ============================================================
// 12. Very long password does not cause server error
// ============================================================

test(
    "extremely long password is handled safely",
    async () => {
        const veryLongPassword =
            "A".repeat(10000);

        const response =
            await loginUser(
                email,
                veryLongPassword
            );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// ============================================================
// 13. Password is case-sensitive
// ============================================================

test(
    "password remains case-sensitive",
    async () => {
        const response =
            await loginUser(
                email,
                "pASSWORD123!"
            );

        assert.equal(
            response.status,
            401
        );
    }
);


// ============================================================
// 14. Email cannot be used with another password
// ============================================================

test(
    "valid email with attacker password is rejected",
    async () => {
        const response =
            await loginUser(
                email,
                "AttackerPassword999!"
            );

        assert.equal(
            response.status,
            401
        );
    }
);


// ============================================================
// 15. Login with whitespace-modified password fails
// ============================================================
test("password whitespace is not silently ignored", async () => {
    const uniqueEmail =
        `whitespace-password-${Date.now()}@example.com`;

    const realPassword = "StrongPassword123!";

    const register = await request(app)
        .post("/api/auth/register")
        .send({
            name: "Whitespace Password",
            email: uniqueEmail,
            password: realPassword
        });

    assert.ok(
        [200, 201].includes(register.statusCode),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    /*
     * Use a unique email for this authentication attempt so that
     * the login rate limiter from the previous security phase
     * does not interfere with this password-validation test.
     */
    const response = await request(app)
        .post("/api/auth/login")
        .set(
            "X-Forwarded-For",
            `10.20.30.${Math.floor(Math.random() * 200) + 1}`
        )
        .send({
            email: uniqueEmail,
            password: ` ${realPassword} `
        });

    assert.notEqual(
        response.statusCode,
        200,
        "Password with surrounding whitespace must not silently authenticate"
    );
});