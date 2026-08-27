import "./env.js";

import test, {
    before,
    beforeEach,
    after,
} from "node:test";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase,
} from "./setup.js";


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
// SECURITY HEADERS
// =========================================================

test(
    "API response includes security headers",
    async () => {

        const response =
            await request(app)
                .get("/api/health");

        assert.ok(
            response.headers
        );

        // Helmet / security middleware commonly provides
        // at least one of these headers.

        const hasSecurityHeader =
            Boolean(
                response.headers["x-content-type-options"] ||
                response.headers["x-frame-options"] ||
                response.headers["content-security-policy"] ||
                response.headers["strict-transport-security"] ||
                response.headers["referrer-policy"]
            );

        assert.equal(
            hasSecurityHeader,
            true
        );
    }
);


// =========================================================
// CONTENT TYPE
// =========================================================

test(
    "API health response uses JSON content type",
    async () => {

        const response =
            await request(app)
                .get("/api/health");

        assert.ok(
            response.headers["content-type"]
                ?.toLowerCase()
                .includes("json")
        );
    }
);


// =========================================================
// SERVER INFORMATION DISCLOSURE
// =========================================================

test(
    "API does not expose detailed server information",
    async () => {

        const response =
            await request(app)
                .get("/api/health");

        const serverHeader =
            response.headers["server"];

        if (serverHeader) {

            assert.notEqual(
                serverHeader.toLowerCase(),
                "express"
            );
        }
    }
);


// =========================================================
// CORS
// =========================================================

test(
    "CORS does not allow arbitrary origin",
    async () => {

        const response =
            await request(app)
                .get("/api/health")
                .set(
                    "Origin",
                    "https://evil-example.com"
                );

        const allowOrigin =
            response.headers["access-control-allow-origin"];

        assert.notEqual(
            allowOrigin,
            "*"
        );

        assert.notEqual(
            allowOrigin,
            "https://evil-example.com"
        );
    }
);


// =========================================================
// HTTP METHOD SECURITY
// =========================================================

test(
    "unsupported HTTP method does not create server error",
    async () => {

        const response =
            await request(app)
                .patch("/api/health");

        assert.notEqual(
            response.status,
            500
        );
    }
);


// =========================================================
// ERROR RESPONSE
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
            500
        );

        assert.equal(
            body.includes("at "),
            false
        );

        assert.equal(
            body.includes("node_modules"),
            false
        );
    }
);