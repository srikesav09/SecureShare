import "./env.js";

import test, {
  before,
  after,
  beforeEach
} from "node:test";

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

test("public registration cannot create ADMIN", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Security Test",
      email: "security@example.com",
      password: "password123",
      role: "ADMIN"
    });

  assert.strictEqual(
    response.status,
    201
  );

  assert.strictEqual(
    response.body.data.role,
    "USER"
  );

  const user =
    await User.findOne({
      email: "security@example.com"
    });

  assert.strictEqual(
    user.role,
    "USER"
  );
});

test("registration rejects invalid input", async () => {
  const response = await request(app)
    .post("/api/auth/register")
    .send({
      name: "A",
      email: "invalid",
      password: "123"
    });

  assert.strictEqual(
    response.status,
    400
  );

  assert.strictEqual(
    response.body.success,
    false
  );
});

test("login rate limiter eventually blocks repeated attempts", async () => {
  await request(app)
    .post("/api/auth/register")
    .send({
      name: "Rate Test",
      email: "rate@example.com",
      password: "password123"
    });

  let blocked = false;

  // Login limiter allows 10 requests.
  // The 11th request should return 429.
  for (let i = 0; i < 11; i++) {
    const response =
      await request(app)
        .post("/api/auth/login")
        .send({
          email: "rate@example.com",
          password: "wrong-password"
        });

    if (response.status === 429) {
      blocked = true;
      break;
    }
  }

  assert.strictEqual(
    blocked,
    true
  );
});

test("security headers are present", async () => {
  const response =
    await request(app)
      .get("/api/health");

  assert.ok(
    response.headers[
      "x-content-type-options"
    ]
  );

  assert.strictEqual(
    response.headers[
      "x-powered-by"
    ],
    undefined
  );
});

test("request ID is generated", async () => {
  const response =
    await request(app)
      .get("/api/health");

  assert.ok(
    response.headers[
      "x-request-id"
    ]
  );

  assert.match(
    response.headers[
      "x-request-id"
    ],
    /^[0-9a-f-]{36}$/i
  );
});

test("CORS header is present", async () => {
    const response = await request(app)
        .get("/api/health")
        .set("Origin", "http://localhost:5173");

    assert.ok(
        response.headers["access-control-allow-origin"],
        "Access-Control-Allow-Origin header is missing"
    );
});