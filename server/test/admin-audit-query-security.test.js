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
import AuditLog from "../src/models/audit.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD = "AuditQuerySecurity123!";

let user;
let token;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `audit-query-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Audit Query User",

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
        `JWT token missing: ${JSON.stringify(login.body)}`
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


    await AuditLog.create([
        {
            user:
                user.id,

            action:
                "TEST_AUDIT",

            resourceType:
                "FILE",

            resourceId:
                user.id,

            status:
                "SUCCESS",

            details: {
                test:
                    "audit-query"
            }
        },
        {
            user:
                user.id,

            action:
                "TEST_AUDIT_2",

            resourceType:
                "FILE",

            resourceId:
                user.id,

            status:
                "SUCCESS",

            details: {
                test:
                    "audit-query-2"
            }
        }
    ]);

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. ADMIN ENDPOINT REQUIRES AUTHENTICATION
   ========================================================= */

test(
    "admin audit endpoint rejects unauthenticated requests",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs"
                );


        assert.equal(
            response.status,
            401
        );

    }
);


/* =========================================================
   2. NORMAL USER CANNOT ACCESS AUDIT LOGS
   ========================================================= */

test(
    "normal user cannot access admin audit logs",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   3. QUERY ROLE CANNOT GRANT ADMIN
   ========================================================= */

test(
    "role query parameter cannot grant admin access",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs?role=ADMIN"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   4. ARRAY ROLE CANNOT GRANT ADMIN
   ========================================================= */

test(
    "array role query parameter cannot grant admin access",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs?role[]=ADMIN&role[]=USER"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   5. USER ID QUERY CANNOT IMPERSONATE ADMIN
   ========================================================= */

test(
    "userId query parameter cannot replace authenticated identity",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/admin/audit-logs?userId=${user.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   6. DUPLICATE USER ID CANNOT BYPASS AUTHORIZATION
   ========================================================= */

test(
    "duplicate userId parameters cannot bypass admin authorization",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/admin/audit-logs?userId=${user.id}&userId=admin`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   7. NOSQL OPERATOR CANNOT BYPASS ADMIN AUTHORIZATION
   ========================================================= */

test(
    "NoSQL role operator cannot bypass admin authorization",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs?role[$ne]=USER"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   8. PAGINATION TYPE CONFUSION
   ========================================================= */

test(
    "invalid pagination parameters do not cause server error",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs?page[$gt]=0&limit[$ne]=null"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   9. FORGED ADMIN HEADER
   ========================================================= */

test(
    "client-supplied admin headers cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
                .set(
                    "X-User-Role",
                    "ADMIN"
                )
                .set(
                    "X-Admin",
                    "true"
                )
                .set(
                    "X-User-ID",
                    String(user.id)
                );


        assert.equal(
            response.status,
            403
        );

    }
);


/* =========================================================
   10. NORMAL USER CANNOT FILTER INTO ADMIN DATA
   ========================================================= */

test(
    "query filters cannot expose admin-only audit data",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/admin/audit-logs?action=DELETE&status=SUCCESS"
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            403
        );


        const body =
            JSON.stringify(
                response.body
            )
                .toLowerCase();


        assert.equal(
            body.includes(
                "audit-logs"
            ),
            false
        );

    }
);
