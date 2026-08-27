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


// =========================================================
// CONSTANTS
// =========================================================

const PASSWORD = "Password123!";


// =========================================================
// HELPERS
// =========================================================

const uniqueEmail = (prefix = "mass") =>
    `${prefix}-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 10)}@example.com`;


/*
 * Register a normal user and return the actual MongoDB
 * document.
 */
const createNormalUser = async () => {

    const email = uniqueEmail("mass-user");

    const response =
        await request(app)
            .post("/api/auth/register")
            .send({
                name: "Mass Assignment User",
                email,
                password: PASSWORD
            });

    assert.equal(
        response.status,
        201,
        `Registration failed: ${JSON.stringify(response.body)}`
    );

    const user =
        await User.findOne({
            email
        });

    assert.ok(
        user,
        "User was not created"
    );

    return {
        user,
        email
    };
};


/*
 * Attempt registration with protected fields.
 *
 * The request must either:
 *
 *   1. be rejected with 400/409/429
 *
 * OR
 *
 *   2. succeed as a normal USER while ignoring
 *      attacker-controlled protected properties.
 */
const registerWithProtectedFields = async ({
    name,
    email,
    password = PASSWORD,
    ...protectedFields
}) => {

    return request(app)
        .post("/api/auth/register")
        .send({
            name,
            email,
            password,
            ...protectedFields
        });
};


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
// ROLE ESCALATION
// =========================================================

test(
    "registration cannot assign ADMIN role",
    async () => {

        const email =
            uniqueEmail("admin-role");

        const response =
            await registerWithProtectedFields({
                name: "Admin Injection",
                email,
                role: "ADMIN"
            });


        /*
         * Registration may succeed because the application
         * intentionally ignores the client-supplied role.
         *
         * Therefore verify the actual database value.
         */
        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.equal(
                user.role,
                "USER",
                "Client was able to assign ADMIN role"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status),
                `Unexpected status: ${response.status}`
            );

        }

    }
);


// =========================================================
// LOWERCASE ADMIN
// =========================================================

test(
    "registration cannot assign lowercase admin role",
    async () => {

        const email =
            uniqueEmail("lower-admin");

        const response =
            await registerWithProtectedFields({
                name: "Lower Admin Injection",
                email,
                role: "admin"
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.equal(
                user.role,
                "USER"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// isAdmin
// =========================================================

test(
    "registration cannot assign isAdmin privilege",
    async () => {

        const email =
            uniqueEmail("is-admin");

        const response =
            await registerWithProtectedFields({
                name: "isAdmin Injection",
                email,
                isAdmin: true
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                user.isAdmin,
                true,
                "Client-controlled isAdmin was stored"
            );

            assert.equal(
                user.role,
                "USER"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// ADMIN BOOLEAN
// =========================================================

test(
    "registration cannot create administrator using admin field",
    async () => {

        const email =
            uniqueEmail("admin-field");

        const response =
            await registerWithProtectedFields({
                name: "Admin Field Injection",
                email,
                admin: true
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                user.admin,
                true
            );

            assert.equal(
                user.role,
                "USER"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// MONGODB _ID INJECTION
// =========================================================

test(
    "registration cannot assign client-controlled _id",
    async () => {

        const email =
            uniqueEmail("custom-id");

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await registerWithProtectedFields({
                name: "Custom ID Injection",
                email,
                _id: fakeId
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                user.id.toString(),
                fakeId,
                "Client was able to control MongoDB _id"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// ID FIELD INJECTION
// =========================================================

test(
    "registration cannot assign client-controlled id",
    async () => {

        const email =
            uniqueEmail("custom-user-id");

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await registerWithProtectedFields({
                name: "ID Injection",
                email,
                id: fakeId
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                user.id.toString(),
                fakeId
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// OWNER FIELD
// =========================================================

test(
    "registration cannot assign owner field",
    async () => {

        const email =
            uniqueEmail("owner-field");

        const fakeOwner =
            "507f1f77bcf86cd799439011";

        const response =
            await registerWithProtectedFields({
                name: "Owner Injection",
                email,
                owner: fakeOwner
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            /*
             * A newly registered user must not receive an
             * attacker-controlled owner property.
             */
            assert.notEqual(
                String(user.owner),
                fakeOwner
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// PASSWORD HASH INJECTION
// =========================================================

test(
    "registration cannot inject passwordHash",
    async () => {

        const email =
            uniqueEmail("password-hash");

        const fakeHash =
            "attacker-controlled-password-hash";

        const response =
            await registerWithProtectedFields({
                name: "Password Hash Injection",
                email,
                passwordHash: fakeHash
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                user.passwordHash,
                fakeHash
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// CREATED AT INJECTION
// =========================================================

test(
    "registration cannot override createdAt",
    async () => {

        const email =
            uniqueEmail("created-at");

        const attackerDate =
            "2000-01-01T00:00:00.000Z";

        const response =
            await registerWithProtectedFields({
                name: "CreatedAt Injection",
                email,
                createdAt: attackerDate
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                new Date(user.createdAt).toISOString(),
                attackerDate,
                "Client was able to override createdAt"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// UPDATED AT INJECTION
// =========================================================

test(
    "registration cannot override updatedAt",
    async () => {

        const email =
            uniqueEmail("updated-at");

        const attackerDate =
            "2000-01-01T00:00:00.000Z";

        const response =
            await registerWithProtectedFields({
                name: "UpdatedAt Injection",
                email,
                updatedAt: attackerDate
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);

            assert.notEqual(
                new Date(user.updatedAt).toISOString(),
                attackerDate,
                "Client was able to override updatedAt"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status)
            );

        }

    }
);


// =========================================================
// MULTIPLE PROTECTED FIELDS
// =========================================================

test(
    "registration ignores multiple attacker-controlled protected fields",
    async () => {

        const email =
            uniqueEmail("multiple-fields");

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await registerWithProtectedFields({
                name: "Multiple Injection",
                email,

                role: "ADMIN",

                isAdmin: true,

                admin: true,

                _id: fakeId,

                id: fakeId,

                owner: fakeId,

                passwordHash:
                    "attacker-password-hash"
            });


        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });

            assert.ok(user);


            /*
             * Most important privilege invariant.
             */
            assert.equal(
                user.role,
                "USER"
            );


            assert.notEqual(
                user.isAdmin,
                true
            );


            assert.notEqual(
                user.admin,
                true
            );


            assert.notEqual(
                user.id.toString(),
                fakeId
            );


            assert.notEqual(
                user.passwordHash,
                "attacker-password-hash"
            );

        } else {

            assert.ok(
                [400, 409, 429].includes(response.status),
                `Unexpected status ${response.status}: ${JSON.stringify(response.body)}`
            );

        }

    }
);


// =========================================================
// ROLE OBJECT INJECTION
// =========================================================

test(
    "registration cannot inject role using an object",
    async () => {

        const email =
            uniqueEmail("role-object");

        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Role Object Injection",

                    email,

                    password: PASSWORD,

                    role: {
                        $ne: "USER"
                    }
                });


        /*
         * The application may either:
         *
         * 1. Reject the malicious field, OR
         * 2. Ignore it and successfully create a normal USER.
         *
         * Both behaviours are secure.
         */
        assert.ok(
            [201, 400, 429].includes(response.status),
            `Unexpected status: ${response.status}: ${JSON.stringify(response.body)}`
        );


        /*
         * If registration succeeded, verify the actual
         * database record rather than trusting the response.
         */
        if (response.status === 201) {

            const user =
                await User.findOne({
                    email
                });


            assert.ok(
                user,
                "User was not found after successful registration"
            );


            /*
             * CRITICAL SECURITY CHECK:
             *
             * The attacker supplied:
             *
             * role: { $ne: "USER" }
             *
             * This must NEVER become a privileged role.
             */
            assert.equal(
                user.role,
                "USER",
                "Object-based role injection created a non-USER account"
            );


            /*
             * Make sure the role is actually a string,
             * not a MongoDB operator object.
             */
            assert.equal(
                typeof user.role,
                "string",
                "User role must be a string"
            );


            assert.notEqual(
                user.role,
                "ADMIN"
            );


            assert.notEqual(
                user.role,
                "admin"
            );
        }
    }
);


// =========================================================
// NAME MASS ASSIGNMENT
// =========================================================

test(
    "normal registration fields still work with protected fields present",
    async () => {

        const email =
            uniqueEmail("normal-registration");

        const response =
            await registerWithProtectedFields({
                name: "Normal User",
                email,

                role: "ADMIN",

                isAdmin: true
            });


        assert.equal(
            response.status,
            201,
            `Normal registration unexpectedly failed: ${JSON.stringify(response.body)}`
        );


        const user =
            await User.findOne({
                email
            });


        assert.ok(user);


        assert.equal(
            user.name,
            "Normal User"
        );


        assert.equal(
            user.email,
            email
        );


        assert.equal(
            user.role,
            "USER"
        );


        assert.notEqual(
            user.isAdmin,
            true
        );

    }
);


// =========================================================
// DATABASE INTEGRITY AFTER ATTACK
// =========================================================

test(
    "mass-assignment attempts cannot modify an existing user's role",
    async () => {

        const { user, email } =
            await createNormalUser();


        assert.equal(
            user.role,
            "USER"
        );


        /*
         * Attempt to register another account using the same
         * email while supplying an administrator role.
         */
        const response =
            await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Role Escalation",
                    email,
                    password: PASSWORD,
                    role: "ADMIN",
                    isAdmin: true
                });


        assert.ok(
            [400, 409, 429].includes(response.status),
            `Unexpected response: ${response.status}`
        );


        const databaseUser =
            await User.findOne({
                email
            });


        assert.ok(
            databaseUser
        );


        assert.equal(
            databaseUser.role,
            "USER",
            "Existing user was escalated to ADMIN"
        );

    }
);