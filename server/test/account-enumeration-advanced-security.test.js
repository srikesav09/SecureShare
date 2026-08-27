import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert/strict";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD =
    "EnumerationSecurity123!";

let existingEmail;


/* =========================================================
   HELPERS
   ========================================================= */

const registerUser = async (
    email,
    password = PASSWORD
) => {

    return request(app)
        .post("/api/auth/register")
        .send({
            name:
                "Enumeration Test User",

            email,

            password
        });
};


const loginUser = async (
    email,
    password
) => {

    return request(app)
        .post("/api/auth/login")
        .send({
            email,
            password
        });
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();

    existingEmail =
        `existing-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const response =
        await registerUser(
            existingEmail
        );


    assert.equal(
        response.status,
        201,
        `Initial registration failed: ${JSON.stringify(response.body)}`
    );

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. EXISTING USER LOGIN
   ========================================================= */

test(
    "existing user can authenticate normally",
    async () => {

        const response =
            await loginUser(
                existingEmail,
                PASSWORD
            );


        assert.equal(
            response.status,
            200
        );

    }
);


/* =========================================================
   2. WRONG PASSWORD
   ========================================================= */

test(
    "wrong password does not reveal whether account exists",
    async () => {

        const response =
            await loginUser(
                existingEmail,
                "WrongPassword999!"
            );


        assert.equal(
            response.status,
            401
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "user exists"
            ),
            false
        );


        assert.equal(
            body.includes(
                "account exists"
            ),
            false
        );


        assert.equal(
            body.includes(
                "email exists"
            ),
            false
        );

    }
);


/* =========================================================
   3. UNKNOWN EMAIL
   ========================================================= */

test(
    "unknown email does not disclose user existence",
    async () => {

        const unknownEmail =
            `unknown-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}@example.com`;


        const response =
            await loginUser(
                unknownEmail,
                PASSWORD
            );


        assert.equal(
            response.status,
            401
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "user not found"
            ),
            false
        );


        assert.equal(
            body.includes(
                "email not found"
            ),
            false
        );


        assert.equal(
            body.includes(
                "account does not exist"
            ),
            false
        );

    }
);


/* =========================================================
   4. EMPTY EMAIL
   ========================================================= */

test(
    "empty email is rejected safely",
    async () => {

        const response =
            await loginUser(
                "",
                PASSWORD
            );


        assert.equal(
            response.status,
            400
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   5. INVALID EMAIL FORMAT
   ========================================================= */

test(
    "invalid email format is rejected safely",
    async () => {

        const response =
            await loginUser(
                "not-an-email",
                PASSWORD
            );


        assert.equal(
            response.status,
            400
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   6. CASE NORMALIZATION
   ========================================================= */

test(
    "email case handling does not expose account existence",
    async () => {

        const uppercaseEmail =
            existingEmail.toUpperCase();


        const response =
            await loginUser(
                uppercaseEmail,
                "WrongPassword999!"
            );


        assert.equal(
            response.status,
            401
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "user not found"
            ),
            false
        );

    }
);


/* =========================================================
   7. DUPLICATE REGISTRATION
   ========================================================= */

test(
    "duplicate registration is handled without internal details",
    async () => {

        const response =
            await registerUser(
                existingEmail
            );


        assert.notEqual(
            response.status,
            500
        );


        assert.ok(
            [400, 409].includes(
                response.status
            ),
            `Unexpected duplicate registration status: ${response.status}`
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "mongodb"
            ),
            false
        );


        assert.equal(
            body.includes(
                "duplicate key"
            ),
            false
        );


        assert.equal(
            body.includes(
                "e11000"
            ),
            false
        );

    }
);


/* =========================================================
   8. DUPLICATE REGISTRATION DOES NOT CREATE SECOND USER
   ========================================================= */

test(
    "duplicate registration does not create another account",
    async () => {

        await registerUser(
            existingEmail
        );


        const count =
            await User.countDocuments({
                email:
                    existingEmail
            });


        assert.equal(
            count,
            1
        );

    }
);


/* =========================================================
   9. OBJECT EMAIL
   ========================================================= */

test(
    "object-valued email cannot bypass account validation",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send({

                    email: {
                        $ne:
                            null
                    },

                    password:
                        PASSWORD

                });


        assert.notEqual(
            response.status,
            200
        );


        assert.notEqual(
            response.status,
            500
        );

    }
);


/* =========================================================
   10. EMAIL REGEX INJECTION
   ========================================================= */

test(
    "regex email injection cannot enumerate accounts",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/auth/login"
                )
                .send({

                    email: {
                        $regex:
                            ".*"
                    },

                    password:
                        {
                            $ne:
                                null
                        }

                });


        assert.notEqual(
            response.status,
            200
        );


        assert.notEqual(
            response.status,
            500
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "mongodb"
            ),
            false
        );


        assert.equal(
            body.includes(
                "mongoose"
            ),
            false
        );

    }
);