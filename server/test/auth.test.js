import "./env.js";

import test, {
  before,
  after,
  beforeEach
} from "node:test";


import jwt from "jsonwebtoken";

import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";

import {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase
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

test("registers a valid USER", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "test@example.com",
      password: "password123"
    });

  assert.strictEqual(response.status, 201);

  assert.strictEqual(
    response.body.success,
    true
  );

  assert.strictEqual(
    response.body.data.role,
    "USER"
  );

  const user = await User.findOne({
    email: "test@example.com"
  });

  assert.ok(user);

  assert.strictEqual(
    user.role,
    "USER"
  );

  assert.notStrictEqual(
    user.password,
    "password123"
  );
});

test("cannot register ADMIN through public registration", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Attacker",
      email: "attacker@example.com",
      password: "password123",
      role: "ADMIN"
    });

  assert.strictEqual(response.status, 201);

  assert.strictEqual(
    response.body.data.role,
    "USER"
  );

  const user = await User.findOne({
    email: "attacker@example.com"
  });

  assert.ok(user);

  assert.strictEqual(
    user.role,
    "USER"
  );
});

test("rejects invalid email", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "invalid-email",
      password: "password123"
    });

  assert.strictEqual(response.status, 400);
});

test("rejects short password", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "test@example.com",
      password: "123"
    });

  assert.strictEqual(response.status, 400);
});

test("rejects short name", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "A",
      email: "test@example.com",
      password: "password123"
    });

  assert.strictEqual(response.status, 400);
});

test("rejects duplicate email", async () => {
  await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "test@example.com",
      password: "password123"
    });

  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Another User",
      email: "test@example.com",
      password: "password123"
    });

  assert.strictEqual(response.status, 409);
});

test("normalizes email to lowercase", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "TEST@EXAMPLE.COM",
      password: "password123"
    });

  assert.strictEqual(response.status, 201);

  const user = await User.findOne({
    email: "test@example.com"
  });

  assert.ok(user);
});

test("login succeeds with correct credentials", async () => {
  await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "test@example.com",
      password: "password123"
    });

  const response = await request(app)
    .post("/api/auth/login")
    .send({
      email: "test@example.com",
      password: "password123"
    });

  assert.strictEqual(response.status, 200);

  assert.strictEqual(
    response.body.success,
    true
  );

  assert.ok(
    response.body.data.token
  );
});

test("login rejects incorrect password", async () => {
  await request(app)
    .post("/api/auth/register")
    .send({
      name: "Test User",
      email: "test@example.com",
      password: "password123"
    });

  const response = await request(app)
    .post("/api/auth/login")
    .send({
      email: "test@example.com",
      password: "wrongpassword"
    });

  assert.strictEqual(response.status, 401);
});

test("login rejects unknown user", async () => {
  const response = await request(app)
    .post("/api/auth/login")
    .send({
      email: "unknown@example.com",
      password: "password123"
    });

  assert.strictEqual(response.status, 401);
});

test("profile requires authentication", async () => {
  const response = await request(app)
    .get("/api/auth/profile");

  assert.strictEqual(response.status, 401);
});

test("authenticated user can retrieve profile", async () => {
    const user = await User.create({
        name: "Profile User",
        email: "profile@example.com",
        password: "password123",
        role: "USER"
    });

    const token = jwt.sign(
        {
            id: user._id.toString(),
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    const response = await request(app)
        .get("/api/auth/profile")
        .set("Authorization", `Bearer ${token}`);

    assert.strictEqual(
        response.status,
        200,
        `Profile request failed: ${JSON.stringify(response.body)}`
    );

    assert.strictEqual(
        response.body.success,
        true
    );

    assert.strictEqual(
        response.body.data.email,
        "profile@example.com"
    );

    assert.strictEqual(
        response.body.data.name,
        "Profile User"
    );

    // Password must never be returned
    assert.strictEqual(
        response.body.data.password,
        undefined
    );
});