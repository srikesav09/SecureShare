import "./env.js";

import test, { before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import jwt from "jsonwebtoken";

import app from "../src/app.js";
import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";
import Share from "../src/models/share.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const JWT_SECRET = process.env.JWT_SECRET;

let userA;
let userB;
let admin;

let tokenA;
let tokenB;
let adminToken;


/* =====================================================
   DATABASE SETUP
===================================================== */

before(async () => {
    await startTestDatabase();
});

beforeEach(async () => {
    await clearTestDatabase();

    userA = await User.create({
        name: "User A",
        email: "usera@example.com",
        password: "password123",
        role: "USER"
    });

    userB = await User.create({
        name: "User B",
        email: "userb@example.com",
        password: "password123",
        role: "USER"
    });

    admin = await User.create({
        name: "Admin User",
        email: "admin@example.com",
        password: "password123",
        role: "ADMIN"
    });

    tokenA = jwt.sign(
        {
            id: userA._id.toString(),
            role: "USER"
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    tokenB = jwt.sign(
        {
            id: userB._id.toString(),
            role: "USER"
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    adminToken = jwt.sign(
        {
            id: admin._id.toString(),
            role: "ADMIN"
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );
});

after(async () => {
    await stopTestDatabase();
});


/* =====================================================
   JWT SECURITY
===================================================== */

test("tampered JWT is rejected", async () => {

    const parts = tokenA.split(".");

    parts[1] = parts[1].slice(0, -1) + "X";

    const tamperedToken = parts.join(".");

    const response = await request(app)
        .get("/api/auth/profile")
        .set(
            "Authorization",
            `Bearer ${tamperedToken}`
        );

    assert.strictEqual(
        response.status,
        401
    );
});


test("expired JWT is rejected", async () => {

    const expiredToken = jwt.sign(
        {
            id: userA._id.toString(),
            role: "USER"
        },
        JWT_SECRET,
        {
            expiresIn: "-1s"
        }
    );

    const response = await request(app)
        .get("/api/auth/profile")
        .set(
            "Authorization",
            `Bearer ${expiredToken}`
        );

    assert.strictEqual(
        response.status,
        401
    );
});


test("JWT signed with wrong secret is rejected", async () => {

    const fakeToken = jwt.sign(
        {
            id: userA._id.toString(),
            role: "USER"
        },
        "completely-wrong-secret",
        {
            expiresIn: "1h"
        }
    );

    const response = await request(app)
        .get("/api/auth/profile")
        .set(
            "Authorization",
            `Bearer ${fakeToken}`
        );

    assert.strictEqual(
        response.status,
        401
    );
});


/* =====================================================
   CROSS-USER FILE AUTHORIZATION
===================================================== */

test("USER cannot download another user's file", async () => {

    const file = await File.create({
        originalName: "private.pdf",
        storedName: "private-file.pdf",
        mimeType: "application/pdf",
        size: 100,

        s3Key:
            `files/${userA._id}/private.enc`,

        owner: userA._id,

        encrypted: true,

        iv:
            "00112233445566778899aabbccddeeff",

        hash: "testhash"
    });

    const response = await request(app)
        .get(
            `/api/files/${file._id}/download`
        )
        .set(
            "Authorization",
            `Bearer ${tokenB}`
        );

    assert.strictEqual(
        response.status,
        403
    );
});


test("USER cannot delete another user's file", async () => {

    const file = await File.create({
        originalName: "private.pdf",
        storedName: "private-file.pdf",
        mimeType: "application/pdf",
        size: 100,

        s3Key:
            `files/${userA._id}/private.enc`,

        owner: userA._id,

        encrypted: true,

        iv:
            "00112233445566778899aabbccddeeff",

        hash: "testhash"
    });

    const response = await request(app)
        .delete(
            `/api/files/${file._id}`
        )
        .set(
            "Authorization",
            `Bearer ${tokenB}`
        );

    assert.strictEqual(
        response.status,
        403
    );
});


test("USER cannot create share link for another user's file", async () => {

    const file = await File.create({
        originalName: "private.pdf",
        storedName: "private-file.pdf",
        mimeType: "application/pdf",
        size: 100,

        s3Key:
            `files/${userA._id}/private.enc`,

        owner: userA._id,

        encrypted: true,

        iv:
            "00112233445566778899aabbccddeeff",

        hash: "testhash"
    });

    const response = await request(app)
        .post(
            `/api/share/${file._id}`
        )
        .set(
            "Authorization",
            `Bearer ${tokenB}`
        )
        .send({});

    assert.strictEqual(
        response.status,
        403
    );
});


/* =====================================================
   SHARE AUTHORIZATION
===================================================== */

test("USER cannot revoke another user's share", async () => {

    const file = await File.create({
        originalName: "private.pdf",
        storedName: "private-file.pdf",
        mimeType: "application/pdf",
        size: 100,

        s3Key:
            `files/${userA._id}/private.enc`,

        owner: userA._id,

        encrypted: true,

        iv:
            "00112233445566778899aabbccddeeff",

        hash: "testhash"
    });

    const share = await Share.create({
        file: file._id,
        owner: userA._id,

        token: "hashed-test-token",

        expiresAt:
            new Date(
                Date.now() + 24 * 60 * 60 * 1000
            ),

        isRevoked: false
    });

    const response = await request(app)
        .delete(
            `/api/share/${share._id}`
        )
        .set(
            "Authorization",
            `Bearer ${tokenB}`
        );

    assert.strictEqual(
        response.status,
        403
    );
});


/* =====================================================
   ADMIN AUTHORIZATION
===================================================== */

test("normal USER cannot access admin audit logs", async () => {

    const response = await request(app)
        .get("/api/admin/audit-logs")
        .set(
            "Authorization",
            `Bearer ${tokenA}`
        );

    assert.strictEqual(
        response.status,
        403
    );
});


test("ADMIN can access audit logs", async () => {

    const response = await request(app)
        .get("/api/admin/audit-logs")
        .set(
            "Authorization",
            `Bearer ${adminToken}`
        );

    assert.strictEqual(
        response.status,
        200
    );

    assert.strictEqual(
        response.body.success,
        true
    );
});