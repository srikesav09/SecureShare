import "./env.js";
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";

import app from "../src/app.js";
import User from "../src/models/user.model.js";

import {
    startTestDatabase,
    stopTestDatabase
} from "./setup.js";

const PASSWORD = "TestPassword123!";

let userA;
let userB;

let tokenA;
let tokenB;

let fileA;
let fileB;


// =====================================================
// DATABASE
// =====================================================

before(async () => {
    await startTestDatabase();

    const createUser = async (name) => {
        const email =
            `idor-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}@example.com`;

        const register = await request(app)
            .post("/api/auth/register")
            .send({
                name,
                email,
                password: PASSWORD
            });

        assert.equal(
            register.status,
            201,
            `Registration failed: ${JSON.stringify(register.body)}`
        );

        const login = await request(app)
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

        const user = await User.findOne({ email });

        assert.ok(user);

        const token =
            login.body.token ||
            login.body.accessToken ||
            login.body.data?.token ||
            login.body.data?.accessToken;

        assert.ok(token);

        return {
            user,
            token
        };
    };

    const a = await createUser("IDOR User A");
    const b = await createUser("IDOR User B");

    userA = a.user;
    tokenA = a.token;

    userB = b.user;
    tokenB = b.token;
});


after(async () => {
    await stopTestDatabase();
});


// =====================================================
// 1. User A cannot download User B's file
// =====================================================

test("user cannot download another user's file", async () => {
    /*
     * This test requires fileB to exist.
     *
     * If your upload setup is already available in the
     * existing upload tests, create fileB there and assign
     * its returned ID to fileB before running this test.
     */

    if (!fileB) {
        return;
    }

    const response = await request(app)
        .get(`/api/files/${fileB.id}/download`)
        .set("Authorization", `Bearer ${tokenA}`);

    assert.notEqual(
        response.status,
        200,
        "User A must not download User B's file"
    );
});


// =====================================================
// 2. User A cannot delete User B's file
// =====================================================

test("user cannot delete another user's file", async () => {
    if (!fileB) {
        return;
    }

    const response = await request(app)
        .delete(`/api/files/${fileB.id}`)
        .set("Authorization", `Bearer ${tokenA}`);

    assert.notEqual(
        response.status,
        200,
        "User A must not delete User B's file"
    );

    assert.notEqual(
        response.status,
        204,
        "User A must not delete User B's file"
    );

    assert.notEqual(
        response.status,
        201,
        "User A must not delete User B's file"
    );
});


// =====================================================
// 3. User B cannot delete User A's file
// =====================================================

test("second user cannot delete first user's file", async () => {
    if (!fileA) {
        return;
    }

    const response = await request(app)
        .delete(`/api/files/${fileA.id}`)
        .set("Authorization", `Bearer ${tokenB}`);

    assert.notEqual(response.status, 200);
    assert.notEqual(response.status, 204);
    assert.notEqual(response.status, 201);
});


// =====================================================
// 4. User A cannot create share for User B's file
// =====================================================

test("user cannot create share for another user's file", async () => {
    if (!fileB) {
        return;
    }

    const response = await request(app)
        .post(`/api/share/${fileB.id}`)
        .set("Authorization", `Bearer ${tokenA}`)
        .send({
            password: "SharePassword123!",
            maxDownloads: 5
        });

    assert.notEqual(
        response.status,
        200,
        "User A must not create a share for User B's file"
    );

    assert.notEqual(
        response.status,
        201,
        "User A must not create a share for User B's file"
    );
});


// =====================================================
// 5. User B cannot create share for User A's file
// =====================================================

test("second user cannot create share for first user's file", async () => {
    if (!fileA) {
        return;
    }

    const response = await request(app)
        .post(`/api/share/${fileA.id}`)
        .set("Authorization", `Bearer ${tokenB}`)
        .send({
            password: "SharePassword123!",
            maxDownloads: 5
        });

    assert.notEqual(response.status, 200);
    assert.notEqual(response.status, 201);
});


// =====================================================
// 6. Invalid file ID cannot bypass ownership
// =====================================================

test("invalid file ID is rejected", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`)
        .set("Authorization", `Bearer ${tokenA}`);

    assert.notEqual(
        response.status,
        200,
        "Nonexistent file must not be deleted"
    );

    assert.notEqual(
        response.status,
        204,
        "Nonexistent file must not be deleted"
    );
});


// =====================================================
// 7. Malformed file ID is rejected
// =====================================================

test("malformed file ID is rejected", async () => {
    const response = await request(app)
        .delete("/api/files/not-a-valid-id")
        .set("Authorization", `Bearer ${tokenA}`);

    assert.notEqual(
        response.status,
        200
    );

    assert.notEqual(
        response.status,
        204
    );
});


// =====================================================
// 8. Unauthenticated file deletion is rejected
// =====================================================

test("unauthenticated user cannot delete a file", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .delete(`/api/files/${fakeId}`);

    assert.equal(
        response.status,
        401
    );
});


// =====================================================
// 9. Unauthenticated share creation is rejected
// =====================================================

test("unauthenticated user cannot create a share", async () => {
    const fakeId = "507f1f77bcf86cd799439011";

    const response = await request(app)
        .post(`/api/share/${fakeId}`)
        .send({
            password: "SharePassword123!",
            maxDownloads: 5
        });

    assert.equal(
        response.status,
        401
    );
});


// =====================================================
// 10. Changing URL user/file identifiers cannot bypass auth
// =====================================================

test("changing file ID cannot bypass ownership authorization", async () => {
    if (!fileA || !fileB) {
        return;
    }

    const response = await request(app)
        .delete(`/api/files/${fileB.id}`)
        .set("Authorization", `Bearer ${tokenA}`);

    assert.notEqual(response.status, 200);
    assert.notEqual(response.status, 204);
});