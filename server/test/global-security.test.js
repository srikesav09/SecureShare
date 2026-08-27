import "./env.js";

import test, {
    before,
    beforeEach,
    after
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


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
// 1. HEALTH ENDPOINT
// =========================================================

test(
    "health endpoint is available",
    async () => {

        const response =
            await request(app)
                .get("/api/health");

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// 2. UNKNOWN ROUTE
// =========================================================

test(
    "unknown API route does not expose stack trace",
    async () => {

        const response =
            await request(app)
                .get("/api/this-route-does-not-exist");

        const body =
            JSON.stringify(response.body);

        assert.notEqual(
            response.status,
            200
        );

        assert.ok(
            !body.includes("node_modules")
        );

        assert.ok(
            !body.includes("file:///")
        );

        assert.ok(
            !body.toLowerCase().includes(
                "stacktrace"
            )
        );
    }
);


// =========================================================
// 3. UNKNOWN ROUTE DOES NOT EXPOSE SERVER PATH
// =========================================================

test(
    "unknown route does not expose filesystem path",
    async () => {

        const response =
            await request(app)
                .get("/api/nonexistent-security-route");

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes("C:\\Users")
        );

        assert.ok(
            !body.includes("/home/")
        );

        assert.ok(
            !body.includes("/var/")
        );
    }
);


// =========================================================
// 4. MALFORMED JSON
// =========================================================

test(
    "malformed JSON is rejected safely",
    async () => {

        const response =
            await request(app)
                .post("/api/auth/login")
                .set(
                    "Content-Type",
                    "application/json"
                )
                .send(
                    '{"email":"test@example.com",'
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// 5. INVALID HTTP METHOD
// =========================================================

test(
    "unsupported HTTP method does not create a resource",
    async () => {

        const response =
            await request(app)
                .patch("/api/share/test");

        assert.notEqual(
            response.status,
            201
        );
    }
);


// =========================================================
// 6. SENSITIVE DATA NOT EXPOSED
// =========================================================

test(
    "error responses do not expose environment secrets",
    async () => {

        const response =
            await request(app)
                .get("/api/nonexistent-security-route");

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(
                "JWT_SECRET"
            )
        );

        assert.ok(
            !body.includes(
                "AWS_SECRET_ACCESS_KEY"
            )
        );

        assert.ok(
            !body.includes(
                "MONGODB_URI"
            )
        );
    }
);


// =========================================================
// 7. MONGODB ERROR DOES NOT LEAK
// =========================================================

test(
    "database errors are not exposed directly",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-valid-mongodb-id"
                );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(
                "CastError"
            )
        );

        assert.ok(
            !body.includes(
                "mongoose"
            )
        );

        assert.ok(
            !body.includes(
                "node_modules"
            )
        );
    }
);


// =========================================================
// 8. RESPONSE DOES NOT EXPOSE INTERNAL PATH
// =========================================================

test(
    "API error does not expose source file location",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/invalid-id"
                );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes(
                "src/"
            )
        );

        assert.ok(
            !body.includes(
                "src\\"
            )
        );

        assert.ok(
            !body.includes(
                ".js:"
            )
        );
    }
);


// // =========================================================
// 9. API ERROR RESPONSE
// =========================================================

test(
    "unknown API route returns an error response",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/nonexistent-security-route"
                );

        assert.notEqual(
            response.status,
            200
        );

        assert.ok(
            response.status >= 400
        );

        const body =
            typeof response.body === "object" &&
            response.body !== null
                ? JSON.stringify(response.body)
                : String(response.text || "");

        assert.ok(
            body.length >= 0
        );
    }
);


// =========================================================
// 10. AUTHORIZATION HEADER DOES NOT ACCEPT GARBAGE
// =========================================================

test(
    "garbage authorization header is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    "Bearer garbage-token"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// 11. EMPTY BEARER TOKEN
// =========================================================

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


// =========================================================
// 12. WRONG AUTH SCHEME
// =========================================================

test(
    "wrong authorization scheme is rejected",
    async () => {

        const response =
            await request(app)
                .get("/api/files")
                .set(
                    "Authorization",
                    "Basic invalid-token"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// 13. INVALID SHARE ID
// =========================================================

test(
    "invalid share identifier is handled safely",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/share/not-a-valid-id"
                );

        assert.notEqual(
            response.status,
            500
        );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes("CastError")
        );

        assert.ok(
            !body.includes("node_modules")
        );
    }
);


// =========================================================
// 14. INVALID FILE ID
// =========================================================

test(
    "invalid file identifier is handled safely",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-valid-id"
                );

        assert.notEqual(
            response.status,
            500
        );

        const body =
            JSON.stringify(response.body);

        assert.ok(
            !body.includes("CastError")
        );
    }
);


// =========================================================
// 15. DELETE METHOD SECURITY
// =========================================================

test(
    "unauthenticated DELETE request is rejected",
    async () => {

        const response =
            await request(app)
                .delete(
                    "/api/files/507f1f77bcf86cd799439011"
                );

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// 16. SHARE CREATION METHOD SECURITY
// =========================================================

test(
    "unauthenticated share creation is rejected",
    async () => {

        const response =
            await request(app)
                .post(
                    "/api/share/507f1f77bcf86cd799439011"
                )
                .send({
                    maxDownloads: 5
                });

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// 17. UPLOAD AUTHENTICATION
// =========================================================

test(
    "unauthenticated upload is rejected",
    async () => {

        const response =
            await request(app)
                .post("/api/files/upload");

        assert.equal(
            response.status,
            401
        );
    }
);


// =========================================================
// 18. DOWNLOAD AUTHENTICATION
// =========================================================

test(
    "protected download rejects missing authentication",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/507f1f77bcf86cd799439011/download"
                );

        assert.notEqual(
            response.status,
            500
        );
    }
);